"""Личный Telegram-бот: менеджер паролей.

Хранилище: SQLite. Логин и пароль шифруются (Fernet = AES-128-CBC + HMAC).
Ключ выводится из мастер-пароля через scrypt и живёт только в памяти.
Бот отвечает только владельцу (OWNER_ID).
"""
import base64
import hashlib
import html
import os
import secrets
import sqlite3
import string
import threading
import time
from functools import wraps

import telebot
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from telebot import types

# ───────────────────────── Настройки ─────────────────────────
load_dotenv()

TOKEN = os.getenv("BOT_TOKEN", "")
OWNER_ID = int(os.getenv("OWNER_ID", "0") or 0)
DB_PATH = os.getenv("DB_PATH", "vault.db")
AUTOLOCK_MIN = int(os.getenv("AUTOLOCK_MINUTES", "5"))
DELETE_AFTER = int(os.getenv("DELETE_AFTER_SECONDS", "30"))

if not TOKEN or not OWNER_ID:
    raise SystemExit("Заполни BOT_TOKEN и OWNER_ID в файле .env")

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

HELP = (
    "🔐 <b>Менеджер паролей</b>\n\n"
    "/unlock — открыть хранилище\n"
    "/lock — закрыть хранилище\n"
    "/add — добавить запись\n"
    "/list [текст] — все записи или поиск\n"
    "/gen [длина] — сгенерировать пароль\n"
    "/cancel — отменить ввод"
)

# ───────────────────────── База данных ─────────────────────────
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db_lock = threading.Lock()

with db:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            service    TEXT NOT NULL,      -- открытым текстом (для поиска)
            login      TEXT NOT NULL,      -- зашифрован
            password   TEXT NOT NULL,      -- зашифрован
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


def q(sql, args=(), one=False):
    with db_lock, db:
        cur = db.execute(sql, args)
        rows = cur.fetchall() if cur.description else []
    if one:
        return rows[0] if rows else None
    return rows


def meta_get(key):
    row = q("SELECT value FROM meta WHERE key=?", (key,), one=True)
    return row[0] if row else None


def meta_set(key, value):
    q("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))


def is_initialized():
    return meta_get("salt") is not None


# ───────────────────────── Криптография ─────────────────────────
_fernet = None          # ключ в памяти; None = хранилище закрыто
_lock_timer = None


def derive_fernet(master: str, salt: bytes) -> Fernet:
    raw = hashlib.scrypt(
        master.encode(), salt=salt,
        n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32,
    )
    return Fernet(base64.urlsafe_b64encode(raw))


def enc(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def dec(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def lock_vault():
    global _fernet, _lock_timer
    _fernet = None
    if _lock_timer:
        _lock_timer.cancel()
        _lock_timer = None


def touch():
    """Продлевает сессию: автоблокировка через AUTOLOCK_MIN минут бездействия."""
    global _lock_timer
    if _lock_timer:
        _lock_timer.cancel()
    _lock_timer = threading.Timer(AUTOLOCK_MIN * 60, lock_vault)
    _lock_timer.daemon = True
    _lock_timer.start()


def unlock_vault(f: Fernet):
    global _fernet
    _fernet = f
    touch()


def gen_password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p)):
            return p


# ───────────────────────── Утилиты ─────────────────────────
def delete_msg(chat_id, message_id):
    try:
        bot.delete_message(chat_id, message_id)
    except Exception:
        pass


def send_temp(chat_id, text, **kw):
    """Секретное сообщение: нельзя переслать, само удалится."""
    msg = bot.send_message(chat_id, text, protect_content=True, **kw)
    t = threading.Timer(DELETE_AFTER, delete_msg, (chat_id, msg.message_id))
    t.daemon = True
    t.start()
    return msg


def _chat_id(obj):
    if isinstance(obj, types.CallbackQuery):
        return obj.message.chat.id
    return obj.chat.id


def owner_only(fn):
    """Игнорирует всех, кроме владельца."""
    @wraps(fn)
    def wrapper(obj, *a, **kw):
        if obj.from_user.id != OWNER_ID:
            return
        return fn(obj, *a, **kw)
    return wrapper


def need_unlock(fn):
    """Пропускает дальше, только если хранилище открыто."""
    @wraps(fn)
    def wrapper(obj, *a, **kw):
        chat = _chat_id(obj)
        if not is_initialized():
            bot.send_message(chat, "Сначала задай мастер-пароль: /start")
            return
        if _fernet is None:
            bot.send_message(chat, "🔒 Хранилище закрыто. Открыть: /unlock")
            return
        touch()
        return fn(obj, *a, **kw)
    return wrapper


def ask(m, text, handler, *args):
    msg = bot.send_message(m.chat.id, text)
    bot.register_next_step_handler(msg, handler, *args)


def cancelled(m) -> bool:
    if (m.text or "").strip().lower() == "/cancel":
        bot.send_message(m.chat.id, "Отменено.")
        return True
    return False


# ───────────────────────── Старт и мастер-пароль ─────────────────────────
@bot.message_handler(commands=["start", "help"])
@owner_only
def cmd_start(m):
    if not is_initialized():
        ask(
            m,
            "👋 Первый запуск. Придумай мастер-пароль (от 10 символов).\n"
            "Он нигде не хранится — если забудешь, данные не восстановить.\n"
            "Сообщение с паролем я удалю.",
            setup_master,
        )
        return
    bot.send_message(m.chat.id, HELP)


@owner_only
def setup_master(m):
    pw = (m.text or "").strip()
    delete_msg(m.chat.id, m.message_id)
    if len(pw) < 10:
        ask(m, "Слишком короткий. Минимум 10 символов, ещё раз:", setup_master)
        return
    salt = os.urandom(16)
    f = derive_fernet(pw, salt)
    meta_set("salt", salt)
    meta_set("check", f.encrypt(b"vault-ok"))
    unlock_vault(f)
    bot.send_message(m.chat.id, "✅ Хранилище создано и открыто.\n\n" + HELP)


@bot.message_handler(commands=["unlock"])
@owner_only
def cmd_unlock(m):
    if not is_initialized():
        return cmd_start(m)
    ask(m, "🔑 Введи мастер-пароль (сообщение удалю):", do_unlock)


@owner_only
def do_unlock(m):
    pw = m.text or ""
    delete_msg(m.chat.id, m.message_id)
    f = derive_fernet(pw, meta_get("salt"))
    try:
        ok = f.decrypt(meta_get("check")) == b"vault-ok"
    except InvalidToken:
        ok = False
    if ok:
        unlock_vault(f)
        bot.send_message(
            m.chat.id,
            f"🔓 Открыто. Автоблокировка через {AUTOLOCK_MIN} мин без действий.",
        )
    else:
        time.sleep(2)  # лёгкая защита от перебора
        bot.send_message(m.chat.id, "❌ Неверный пароль.")


@bot.message_handler(commands=["lock"])
@owner_only
def cmd_lock(m):
    lock_vault()
    bot.send_message(m.chat.id, "🔒 Хранилище закрыто.")


@bot.message_handler(commands=["cancel"])
@owner_only
def cmd_cancel(m):
    bot.send_message(m.chat.id, "Нечего отменять.")


# ───────────────────────── Добавление записи ─────────────────────────
@bot.message_handler(commands=["add"])
@owner_only
@need_unlock
def cmd_add(m):
    ask(m, "Название сервиса (например, github.com):", add_service)


@owner_only
@need_unlock
def add_service(m):
    if cancelled(m):
        return
    service = (m.text or "").strip()
    if not service:
        return ask(m, "Нужен текст. Название сервиса:", add_service)
    ask(m, "Логин / email:", add_login, service)


@owner_only
@need_unlock
def add_login(m, service):
    if cancelled(m):
        return
    login = (m.text or "").strip()
    if not login:
        return ask(m, "Нужен текст. Логин / email:", add_login, service)
    delete_msg(m.chat.id, m.message_id)
    ask(m, "Пароль: отправь свой или напиши /gen — сгенерирую.", add_password, service, login)


@owner_only
@need_unlock
def add_password(m, service, login):
    if cancelled(m):
        return
    text = (m.text or "").strip()
    delete_msg(m.chat.id, m.message_id)
    generated = text.lower() in ("gen", "/gen")
    password = gen_password() if generated else text
    if not password:
        return ask(m, "Нужен текст. Пароль или /gen:", add_password, service, login)

    q(
        "INSERT INTO entries(service, login, password) VALUES(?, ?, ?)",
        (service, enc(login), enc(password)),
    )
    bot.send_message(m.chat.id, f"✅ Сохранено: <b>{html.escape(service)}</b>")
    if generated:
        send_temp(m.chat.id, f"Сгенерированный пароль:\n<code>{html.escape(password)}</code>")


# ───────────────────────── Список и поиск ─────────────────────────
@bot.message_handler(commands=["list", "get"])
@owner_only
@need_unlock
def cmd_list(m):
    parts = (m.text or "").split(maxsplit=1)
    query = parts[1].strip().lower() if len(parts) > 1 else ""

    rows = q("SELECT id, service FROM entries")
    rows = [r for r in rows if query in r[1].lower()]
    rows.sort(key=lambda r: r[1].lower())

    if not rows:
        bot.send_message(
            m.chat.id,
            "Ничего не найдено." if query else "Пока пусто. Добавь запись: /add",
        )
        return

    shown = rows[:50]
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(*[
        types.InlineKeyboardButton(s, callback_data=f"show:{i}") for i, s in shown
    ])
    title = f"Найдено: {len(rows)}" if query else f"Записей: {len(rows)}"
    if len(rows) > len(shown):
        title += f" (показаны первые {len(shown)}, уточни поиск)"
    bot.send_message(m.chat.id, title, reply_markup=kb)


def show_entry(chat_id, entry_id):
    row = q("SELECT service, login, password FROM entries WHERE id=?", (entry_id,), one=True)
    if not row:
        bot.send_message(chat_id, "Запись не найдена.")
        return
    service, login_enc, pw_enc = row
    try:
        login, password = dec(login_enc), dec(pw_enc)
    except InvalidToken:
        bot.send_message(chat_id, "⚠️ Не удалось расшифровать запись.")
        return

    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("🗑 Удалить запись", callback_data=f"del:{entry_id}"))
    send_temp(
        chat_id,
        f"🔑 <b>{html.escape(service)}</b>\n"
        f"Логин: <code>{html.escape(login)}</code>\n"
        f"Пароль: <code>{html.escape(password)}</code>\n\n"
        f"⏱ Исчезнет через {DELETE_AFTER} с",
        reply_markup=kb,
    )


@bot.callback_query_handler(func=lambda c: True)
@owner_only
@need_unlock
def on_callback(c):
    bot.answer_callback_query(c.id)
    chat_id = c.message.chat.id
    action, _, arg = (c.data or "").partition(":")

    if action == "show" and arg.isdigit():
        show_entry(chat_id, int(arg))

    elif action == "del" and arg.isdigit():
        kb = types.InlineKeyboardMarkup()
        kb.add(
            types.InlineKeyboardButton("✅ Да, удалить", callback_data=f"delyes:{arg}"),
            types.InlineKeyboardButton("Отмена", callback_data="no:0"),
        )
        bot.edit_message_reply_markup(chat_id, c.message.message_id, reply_markup=kb)

    elif action == "delyes" and arg.isdigit():
        q("DELETE FROM entries WHERE id=?", (int(arg),))
        delete_msg(chat_id, c.message.message_id)
        bot.send_message(chat_id, "🗑 Запись удалена.")

    elif action == "no":
        delete_msg(chat_id, c.message.message_id)


# ───────────────────────── Генератор ─────────────────────────
@bot.message_handler(commands=["gen"])
@owner_only
def cmd_gen(m):
    parts = (m.text or "").split()
    n = 20
    if len(parts) > 1 and parts[1].isdigit():
        n = max(8, min(int(parts[1]), 64))
    send_temp(m.chat.id, f"<code>{html.escape(gen_password(n))}</code>")


# ───────────────────────── Запуск ─────────────────────────
if __name__ == "__main__":
    try:
        bot.set_my_commands([
            types.BotCommand("unlock", "Открыть хранилище"),
            types.BotCommand("lock", "Закрыть хранилище"),
            types.BotCommand("add", "Добавить запись"),
            types.BotCommand("list", "Список / поиск"),
            types.BotCommand("gen", "Сгенерировать пароль"),
        ])
    except Exception:
        pass
    print("Бот запущен. Ctrl+C — остановить.")
    bot.infinity_polling(skip_pending=True)
