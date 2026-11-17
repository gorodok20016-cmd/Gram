#!/usr/bin/env python3
"""Albertgram — сервер мессенджера (только стандартная библиотека Python).
Запуск:  python server.py [--port 8000]   затем открой http://IP:8000
Бот-API совместим с Telegram (getMe, getUpdates, sendMessage, editMessageText, deleteMessage, answerCallbackQuery)."""
import argparse, base64, hashlib, hmac, json, os, re, secrets, sqlite3, struct, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB = sqlite3.connect(os.environ.get("ALBERT_DB", str(HERE / "albertgram.db")), check_same_thread=False)
LK, EV, VER = threading.RLock(), threading.Condition(), [0]
FAILS = {}
RESERVED = {"papochka", "telegram", "admin", "support", "botfather"}


def q(sql, a=()):
    with LK:
        c = DB.execute(sql, a)
        DB.commit()
        return c.fetchall() if c.description else c.lastrowid


DB.executescript("""
create table if not exists users(id integer primary key, username text unique collate nocase, name text, pw text, salt text, totp text,
 active int default 0, is_bot int default 0, owner int, token text, verified int default 0, banned int default 0, created real);
create table if not exists sessions(token text primary key, uid int);
create table if not exists chats(id integer primary key, type text, title text, owner int);
create table if not exists members(chat int, uid int, primary key(chat, uid));
create table if not exists msgs(id integer primary key autoincrement, chat int, sender int, text text, markup text, ts real, edited int default 0, deleted int default 0);
create table if not exists updates(id integer primary key autoincrement, bot int, body text);
create table if not exists state(uid int primary key, st text, data text);""")
KEYF = HERE / "admin.key"
if not KEYF.exists():
    KEYF.write_text(secrets.token_hex(8))
ADMIN_KEY = KEYF.read_text().strip()
r = q("select id from users where username='Papochka'")
PAP = r[0][0] if r else q("insert into users(username,name,active,is_bot,verified,created) values('Papochka','Папочка',1,1,1,?)", (time.time(),))


def bump():
    with EV:
        VER[0] += 1
        EV.notify_all()


def totp(secret, t=None):
    c = int((t or time.time()) // 30)
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", c), "sha1").digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6)


def totp_ok(secret, code):
    return any(hmac.compare_digest(totp(secret, time.time() + d * 30), str(code).strip()) for d in (-1, 0, 1))


def hpw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 150000).hex()


def user(uid):
    r = q("select id,username,name,verified,is_bot,banned from users where id=?", (uid,))
    return r[0] if r else None


def U(r):
    return {"id": r[0], "username": r[1], "name": r[2], "verified": bool(r[3]), "bot": bool(r[4])}


def is_admin(uid):
    u = user(uid)
    return bool(u and u[1].lower() == "albert" and not u[4])


def member(chat, uid):
    return bool(q("select 1 from members where chat=? and uid=?", (chat, uid)))


def botmsg(mid):
    cid, sid, text, ts = q("select chat,sender,text,ts from msgs where id=?", (mid,))[0]
    ct, title = q("select type,title from chats where id=?", (cid,))[0]
    s = user(sid)
    d = {"message_id": mid, "from": {"id": s[0], "is_bot": bool(s[4]), "first_name": s[2], "username": s[1]},
         "chat": {"id": cid, "type": "private" if ct == "private" else "group"}, "date": int(ts), "text": text}
    if ct != "private":
        d["chat"]["title"] = title
    if text.startswith("/"):
        d["entities"] = [{"type": "bot_command", "offset": 0, "length": len(text.split()[0])}]
    return d


def push(bot, body):
    q("insert into updates(bot,body) values(?,?)", (bot, json.dumps(body)))
    bump()


def post(chat, sender, text, markup=None):
    mid = q("insert into msgs(chat,sender,text,markup,ts) values(?,?,?,?,?)", (chat, sender, text, json.dumps(markup) if markup else None, time.time()))
    bump()
    if not user(sender)[4]:
        for (b,) in q("select u.id from members m join users u on u.id=m.uid where m.chat=? and u.is_bot=1 and u.id!=?", (chat, sender)):
            if b == PAP:
                threading.Thread(target=papochka, args=(sender, chat, text), daemon=True).start()
            else:
                push(b, {"message": botmsg(mid)})
    return mid


# ───────── Папочка (создание ботов) ─────────
def papochka(uid, chat, text):
    say = lambda t: post(chat, PAP, t)
    t = text.strip()
    st = q("select st,data from state where uid=?", (uid,))
    st, data = st[0] if st else ("", "")
    cmd = t.split()[0].lower().split("@")[0] if t.startswith("/") else ""
    arg = t[len(t.split()[0]):].strip() if cmd else ""
    setst = lambda s, d="": q("insert or replace into state(uid,st,data) values(?,?,?)", (uid, s, d))
    own = lambda n: q("select id,username from users where is_bot=1 and owner=? and username=?", (uid, n.lstrip("@")))
    if cmd in ("/start", "/help"):
        return say("Я Папочка ✔ — создаю ботов.\n/newbot — создать бота\n/mybots — мои боты\n/token @бот — показать токен\n/revoke @бот — новый токен\n/deletebot @бот — удалить\n/cancel — отмена")
    if cmd == "/cancel":
        setst("")
        return say("Ок, отменил.")
    if cmd == "/newbot":
        setst("name")
        return say("Как назвать бота? Пришли имя (например: Мой помощник).")
    if cmd == "/mybots":
        r = q("select username,name from users where is_bot=1 and owner=?", (uid,))
        return say("\n".join(f"@{u} — {n}" for u, n in r) if r else "У тебя пока нет ботов. /newbot")
    if cmd in ("/token", "/revoke", "/deletebot"):
        b = own(arg)
        if not b:
            return say("Не нашёл твоего бота. Пример: " + cmd + " @mybot")
        if cmd == "/token":
            return say("Токен @%s:\n%s" % (b[0][1], q("select token from users where id=?", (b[0][0],))[0][0]))
        if cmd == "/revoke":
            tk = f"{b[0][0]}:{secrets.token_urlsafe(24)}"
            q("update users set token=? where id=?", (tk, b[0][0]))
            return say("Новый токен:\n" + tk)
        q("delete from users where id=?", (b[0][0],))
        q("delete from members where uid=?", (b[0][0],))
        q("delete from updates where bot=?", (b[0][0],))
        return say("Бот удалён.")
    if st == "name" and not cmd:
        setst("user", t[:40])
        return say("Теперь придумай username. Он должен заканчиваться на bot (например: alberthelperbot).")
    if st == "user" and not cmd:
        un = t.lstrip("@")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,28}[Bb][Oo][Tt]", un):
            return say("Username: латиница, цифры, _, длина 5–32, обязательно на конце bot. Попробуй ещё.")
        if un.lower() in RESERVED or q("select 1 from users where username=?", (un,)):
            return say("Этот username занят. Придумай другой.")
        bid = q("insert into users(username,name,active,is_bot,owner,verified,created) values(?,?,1,1,?,0,?)", (un, data, uid, time.time()))
        tk = f"{bid}:{secrets.token_urlsafe(24)}"
        q("update users set token=? where id=?", (tk, bid))
        setst("")
        return say(f"Готово! Бот @{un} создан.\nТокен (никому не показывай):\n{tk}\n\nAPI: http://ТВОЙ_СЕРВЕР/bot{{токен}}/метод — как у Telegram.")
    say("Не понял. Напиши /help")


# ───────── Бот-API (как у Telegram) ─────────
def get_updates(bid, a):
    off, to = int(a.get("offset") or 0), min(int(a.get("timeout") or 0), 25)
    if off > 0:
        q("delete from updates where bot=? and id<?", (bid, off))
    end = time.time() + to
    while True:
        rows = q("select id,body from updates where bot=? and id>=? order by id limit 100", (bid, off))
        if rows or time.time() >= end:
            return [dict(json.loads(b), update_id=i) for i, b in rows]
        with EV:
            EV.wait(min(1, max(0.05, end - time.time())))


def markup_of(a):
    m = a.get("reply_markup")
    if isinstance(m, str) and m:
        try:
            m = json.loads(m)
        except Exception:
            m = None
    return m if isinstance(m, dict) else None


def bot_api(tok, method, a):
    r = q("select id,username,name from users where token=? and is_bot=1", (tok,))
    if not r:
        return 401, {"ok": False, "error_code": 401, "description": "Unauthorized"}
    bid, bun, bn = r[0]
    m = method.lower()
    try:
        if m == "getme":
            res = {"id": bid, "is_bot": True, "first_name": bn, "username": bun, "can_join_groups": True, "can_read_all_group_messages": True}
        elif m == "getupdates":
            res = get_updates(bid, a)
        elif m in ("deletewebhook", "setmycommands", "answercallbackquery", "deletemycommands"):
            res = True
        elif m == "sendmessage":
            chat = int(a["chat_id"])
            if not member(chat, bid):
                return 400, {"ok": False, "error_code": 400, "description": "Bad Request: chat not found"}
            res = botmsg(post(chat, bid, str(a.get("text", "")), markup_of(a)))
        elif m == "editmessagetext":
            mid = int(a["message_id"])
            if not q("select 1 from msgs where id=? and sender=?", (mid, bid)):
                return 400, {"ok": False, "error_code": 400, "description": "Bad Request: message can't be edited"}
            mk = markup_of(a)
            q("update msgs set text=?,markup=?,edited=1 where id=?", (str(a.get("text", "")), json.dumps(mk) if mk else None, mid))
            bump()
            res = botmsg(mid)
        elif m == "deletemessage":
            q("update msgs set deleted=1 where id=? and chat=?", (int(a["message_id"]), int(a["chat_id"])))
            bump()
            res = True
        else:
            return 404, {"ok": False, "error_code": 404, "description": "Not Found: метод пока не реализован"}
    except (KeyError, ValueError):
        return 400, {"ok": False, "error_code": 400, "description": "Bad Request: неверные параметры"}
    return 200, {"ok": True, "result": res}


# ───────── API мессенджера ─────────
class Err(Exception):
    def __init__(self, msg, code=400):
        self.msg, self.code = msg, code


def new_session(uid):
    t = secrets.token_hex(24)
    q("insert into sessions(token,uid) values(?,?)", (t, uid))
    return t


def chat_view(cid, typ, title, uid):
    o = {"id": cid, "type": typ, "title": title, "verified": False, "bot": False}
    if typ == "private":
        r = q("select u.id,u.username,u.name,u.verified,u.is_bot from members m join users u on u.id=m.uid where m.chat=? and u.id!=?", (cid, uid))
        if r:
            o.update(title=r[0][2], username=r[0][1], verified=bool(r[0][3]), bot=bool(r[0][4]))
    l = q("select text,ts from msgs where chat=? and deleted=0 order by id desc limit 1", (cid,))
    o["last"], o["ts"] = (l[0][0][:60], l[0][1]) if l else ("", 0)
    return o


def private_chat(a, b):
    r = q("select c.id from chats c join members x on x.chat=c.id and x.uid=? join members y on y.chat=c.id and y.uid=? where c.type='private'", (a, b))
    if r:
        return r[0][0]
    cid = q("insert into chats(type,title,owner) values('private','',?)", (a,))
    q("insert into members values(?,?)", (cid, a))
    if a != b:
        q("insert into members values(?,?)", (cid, b))
    return cid


def route(method, path, a, tok):
    if path == "/api/register":
        un, pw, name = str(a.get("username", "")).strip().lstrip("@"), str(a.get("password", "")), str(a.get("name", "")).strip()[:40]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", un):
            raise Err("Username: латиница, цифры и _, 5–32 символа, начинается с буквы")
        if len(pw) < 8:
            raise Err("Пароль минимум 8 символов")
        if un.lower() in RESERVED or (un.lower() == "albert" and a.get("invite") != ADMIN_KEY):
            raise Err("Этот username зарезервирован", 403)
        if q("select 1 from users where username=? and active=1", (un,)):
            raise Err("Username занят")
        q("delete from users where username=? and active=0", (un,))
        salt, sec = secrets.token_hex(16), base64.b32encode(secrets.token_bytes(10)).decode()
        q("insert into users(username,name,pw,salt,totp,created) values(?,?,?,?,?,?)", (un, name or un, hpw(pw, salt), salt, sec, time.time()))
        return {"secret": sec, "uri": f"otpauth://totp/Albertgram:{un}?secret={sec}&issuer=Albertgram"}
    if path == "/api/confirm":
        r = q("select id,totp from users where username=? and active=0", (str(a.get("username", "")),))
        if not r or not totp_ok(r[0][1], a.get("code", "")):
            raise Err("Неверный код")
        q("update users set active=1 where id=?", (r[0][0],))
        return {"token": new_session(r[0][0])}
    if path == "/api/login":
        un = str(a.get("username", "")).strip().lstrip("@")
        f = FAILS.get(un.lower(), [0, 0])
        if f[0] >= 5 and time.time() - f[1] < 300:
            raise Err("Слишком много попыток. Подожди 5 минут", 429)
        r = q("select id,pw,salt,totp,banned from users where username=? and active=1 and is_bot=0", (un,))
        if not r or not hmac.compare_digest(r[0][1], hpw(str(a.get("password", "")), r[0][2])) or not totp_ok(r[0][3], a.get("code", "")):
            FAILS[un.lower()] = [f[0] + 1, time.time()]
            raise Err("Неверный логин, пароль или код 2FA", 401)
        if r[0][4]:
            raise Err("Аккаунт заблокирован", 403)
        FAILS.pop(un.lower(), None)
        return {"token": new_session(r[0][0])}
    s = q("select uid from sessions where token=?", (tok,))
    if not s:
        raise Err("Нужен вход", 401)
    uid = s[0][0]
    me = user(uid)
    if me[5]:
        raise Err("Аккаунт заблокирован", 403)
    if path == "/api/me":
        return dict(U(me), admin=is_admin(uid))
    if path == "/api/wait":
        v, end = int(a.get("v") or 0), time.time() + 20
        with EV:
            while VER[0] == v and time.time() < end:
                EV.wait(1)
        return {"v": VER[0]}
    if path == "/api/chats":
        rows = q("select c.id,c.type,c.title from chats c join members m on m.chat=c.id where m.uid=?", (uid,))
        return {"chats": sorted((chat_view(*r, uid) for r in rows), key=lambda c: -c["ts"])}
    if path == "/api/search":
        s_ = "%" + str(a.get("q", "")).lstrip("@") + "%"
        return {"users": [U(x) for x in q("select id,username,name,verified,is_bot,banned from users where active=1 and banned=0 and id!=? and (username like ? or name like ?) limit 20", (uid, s_, s_))]}
    if path == "/api/chat/open":
        t = q("select id from users where username=? and active=1", (str(a.get("username", "")).lstrip("@"),))
        if not t:
            raise Err("Пользователь не найден")
        return {"chat": private_chat(uid, t[0][0])}
    if path == "/api/group":
        title = str(a.get("title", "")).strip()[:60]
        if not title:
            raise Err("Нужно название")
        cid = q("insert into chats(type,title,owner) values('group',?,?)", (title, uid))
        q("insert into members values(?,?)", (cid, uid))
        for un in a.get("members", []):
            t = q("select id from users where username=? and active=1 and id!=?", (str(un).lstrip("@").strip(), PAP))
            if t:
                q("insert or ignore into members values(?,?)", (cid, t[0][0]))
        bump()
        return {"chat": cid}
    if path == "/api/msgs":
        cid = int(a.get("chat", 0))
        if not member(cid, uid):
            raise Err("Нет доступа", 403)
        out = []
        for i, sid, text, mk, ts, ed in reversed(q("select id,sender,text,markup,ts,edited from msgs where chat=? and deleted=0 order by id desc limit 100", (cid,))):
            out.append({"id": i, "from": U(user(sid)) if user(sid) else {"id": sid, "name": "?"}, "text": text, "markup": json.loads(mk) if mk else None, "ts": ts, "edited": bool(ed)})
        return {"msgs": out}
    if path == "/api/send":
        cid, text = int(a.get("chat", 0)), str(a.get("text", "")).strip()[:4000]
        if not member(cid, uid) or not text:
            raise Err("Нельзя отправить")
        return {"id": post(cid, uid, text)}
    if path in ("/api/edit", "/api/delete"):
        m = q("select id from msgs where id=? and sender=? and deleted=0", (int(a.get("id", 0)), uid))
        if not m:
            raise Err("Сообщение не найдено")
        if path == "/api/edit":
            q("update msgs set text=?,edited=1 where id=?", (str(a.get("text", "")).strip()[:4000], m[0][0]))
        else:
            q("update msgs set deleted=1 where id=?", (m[0][0],))
        bump()
        return {"ok": True}
    if path == "/api/cb":
        m = q("select chat,sender from msgs where id=? and deleted=0", (int(a.get("msg", 0)),))
        if not m or not member(m[0][0], uid):
            raise Err("Сообщение не найдено")
        push(m[0][1], {"callback_query": {"id": secrets.token_hex(6), "from": {"id": uid, "is_bot": False, "first_name": me[2], "username": me[1]},
                                          "message": botmsg(int(a["msg"])), "chat_instance": "0", "data": str(a.get("data", ""))[:64]}})
        return {"ok": True}
    if path.startswith("/api/admin/"):
        if not is_admin(uid):
            raise Err("Только для @albert", 403)
        if path.endswith("/users"):
            return {"users": [dict(zip(("id", "username", "name", "verified", "bot", "banned"), x)) for x in q("select id,username,name,verified,is_bot,banned from users where active=1 order by id desc limit 200")]}
        if path.endswith("/stats"):
            n = lambda s: q(s)[0][0]
            return {"users": n("select count(*) from users where is_bot=0 and active=1"), "bots": n("select count(*) from users where is_bot=1"), "chats": n("select count(*) from chats"), "msgs": n("select count(*) from msgs")}
        if path.endswith("/set"):
            f, tid = a.get("field"), int(a.get("id", 0))
            if f not in ("banned", "verified") or (f == "banned" and (is_admin(tid) or tid == PAP)):
                raise Err("Нельзя")
            q(f"update users set {f}=? where id=?", (1 if a.get("value") else 0, tid))
            if f == "banned" and a.get("value"):
                q("delete from sessions where uid=?", (tid,))
            bump()
            return {"ok": True}
    raise Err("Не найдено", 404)


def find_page():
    for f in HERE.iterdir():
        if f.name.lower() in ("albertgram.html", "index.html"):
            return f
    return HERE / "albertgram.html"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *x):
        pass

    def out(self, obj, code=200, raw=None, ctype="application/json; charset=utf-8"):
        b = raw if raw is not None else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()
        self.wfile.write(b)

    def handle_any(self):
        u = urllib.parse.urlparse(self.path)
        a = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if body:
            try:
                a.update(json.loads(body))
            except Exception:
                a.update({k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()})
        if self.command == "GET" and u.path in ("/", "/index.html"):
            p = find_page()
            return self.out(None, raw=p.read_bytes() if p.exists() else b"albertgram.html not found", ctype="text/html; charset=utf-8")
        m = re.match(r"/bot([^/]+)/([A-Za-z]+)$", u.path)
        if m:
            code, obj = bot_api(urllib.parse.unquote(m.group(1)), m.group(2), a)
            return self.out(obj, code)
        tok = (self.headers.get("Authorization") or "").replace("Bearer ", "") or a.get("t", "")
        try:
            return self.out(route(self.command, u.path, a, tok))
        except Err as e:
            return self.out({"error": e.msg}, e.code)
        except Exception as e:
            print("ERR", u.path, repr(e))
            return self.out({"error": "Ошибка сервера"}, 500)

    def do_OPTIONS(self):
        self.out({})

    do_GET = do_POST = handle_any


def main(port=8000, host="0.0.0.0"):
    print(f"Albertgram: http://localhost:{port}\nКлюч для регистрации админа @albert: {ADMIN_KEY}  (файл admin.key, никому не показывай)")
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    main(ap.parse_args().port)
