#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
দোকান — Termux-এ চালানোর মতো পূর্ণাঙ্গ ই-কমার্স ওয়েবসাইট (দারাজ-স্টাইল)
=====================================================================
শুধু Python লাগে। কিছু ইনস্টল করতে হয় না (pip/npm নেই)। ডাটাবেস: SQLite।

ইনস্টল (Termux-এ একবারই):
    pkg update -y && pkg install python -y
    termux-setup-storage
    cp ~/storage/downloads/dokan.py ~/

প্রথমবার চালালে অ্যাডমিন ইউজারনেম ও পাসওয়ার্ড বানাতে বলবে (কোনো ডিফল্ট পাসওয়ার্ড নেই):
    python dokan.py                 # দোকান চালু  -> http://127.0.0.1:8080
    python dokan.py --demo          # নমুনা পণ্যসহ (প্রথমবার দেখার জন্য)
    python dokan.py --lan           # একই Wi-Fi-র অন্য ফোনেও খুলবে
    python dokan.py --port 9000     # অন্য পোর্ট
    python dokan.py --reset-admin   # পাসওয়ার্ড ভুলে গেলে (২-ধাপ যাচাইও বন্ধ হবে)
    python dokan.py --backup        # ডাটাবেস ও ছবির ব্যাকআপ (tar.gz)

ঠিকানা:
    দোকান         : http://127.0.0.1:8080/
    অ্যাডমিন প্যানেল: http://127.0.0.1:8080/admin

ডেটা থাকে ~/dokan-data ফোল্ডারে (shop.db + uploads)।

নিরাপত্তা ব্যবস্থা (সংক্ষেপে):
  * পাসওয়ার্ড PBKDF2-SHA256 (৬ লক্ষ রাউন্ড) + র‍্যান্ডম salt দিয়ে সংরক্ষিত; মূল পাসওয়ার্ড কোথাও থাকে না
  * শক্ত পাসওয়ার্ড নীতি, ভুল চেষ্টায় সাময়িক লক (IP + ইউজার), ঐচ্ছিক ২-ধাপ যাচাই (TOTP)
  * সেশন কুকি: HttpOnly + SameSite=Strict, ৩০ মিনিট নিষ্ক্রিয় থাকলে অটো লগআউট, সর্বোচ্চ ১২ ঘণ্টা
  * প্রতিটি অ্যাডমিন পরিবর্তনে CSRF টোকেন ও Origin যাচাই; অডিট লগ
  * দাম/স্টক/কুপন সবসময় সার্ভারে যাচাই হয় — ব্রাউজারের পাঠানো দামে বিশ্বাস করা হয় না
  * কড়া CSP: শুধু নিজের স্ক্রিপ্ট চলে; সব ইনপুট escape করা
"""

import argparse
import base64
import calendar
import contextlib
import csv
import getpass
import hashlib
import hmac
import html
import io
import json
import math
import os
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import threading
import time
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

# ==========================================================================
# ১. সেটিংস ও ধ্রুবক
# ==========================================================================
DATA_DIR = Path(os.environ.get("DOKAN_DIR", str(Path.home() / "dokan-data")))
DB_PATH = DATA_DIR / "shop.db"
UP_DIR = DATA_DIR / "uploads"
SESSION_IDLE = 30 * 60          # ৩০ মিনিট নিষ্ক্রিয় থাকলে লগআউট
SESSION_MAX = 12 * 3600         # সর্বোচ্চ ১২ ঘণ্টা
PBKDF2_ITERS = 600_000          # OWASP-এর সুপারিশ (SHA-256)
MAX_JSON = 2 * 1024 * 1024
MAX_UPLOAD = 4 * 1024 * 1024
BN = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")
CODE_ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

DISTRICTS = ["ঢাকা", "গাজীপুর", "নারায়ণগঞ্জ", "নরসিংদী", "মানিকগঞ্জ", "মুন্সীগঞ্জ", "কিশোরগঞ্জ", "টাঙ্গাইল",
             "ফরিদপুর", "গোপালগঞ্জ", "মাদারীপুর", "রাজবাড়ী", "শরীয়তপুর", "চট্টগ্রাম", "কক্সবাজার", "কুমিল্লা",
             "ফেনী", "ব্রাহ্মণবাড়িয়া", "রাঙ্গামাটি", "নোয়াখালী", "চাঁদপুর", "লক্ষ্মীপুর", "খাগড়াছড়ি", "বান্দরবান",
             "সিলেট", "হবিগঞ্জ", "মৌলভীবাজার", "সুনামগঞ্জ", "রাজশাহী", "বগুড়া", "নাটোর", "নওগাঁ", "পাবনা",
             "সিরাজগঞ্জ", "চাঁপাইনবাবগঞ্জ", "জয়পুরহাট", "খুলনা", "যশোর", "সাতক্ষীরা", "বাগেরহাট", "কুষ্টিয়া",
             "মাগুরা", "নড়াইল", "চুয়াডাঙ্গা", "মেহেরপুর", "ঝিনাইদহ", "বরিশাল", "পটুয়াখালী", "ভোলা", "পিরোজপুর",
             "ঝালকাঠি", "বরগুনা", "রংপুর", "দিনাজপুর", "কুড়িগ্রাম", "গাইবান্ধা", "লালমনিরহাট", "নীলফামারী",
             "পঞ্চগড়", "ঠাকুরগাঁও", "ময়মনসিংহ", "জামালপুর", "নেত্রকোণা", "শেরপুর"]

# অর্ডারের অবস্থা কোথা থেকে কোথায় যেতে পারে
FLOW = {
    "pending": ["confirmed", "cancelled"],
    "confirmed": ["processing", "shipped", "cancelled"],
    "processing": ["shipped", "cancelled"],
    "shipped": ["delivered", "returned"],
    "delivered": ["returned"],
    "cancelled": [],
    "returned": [],
}
STOCK_RESTORE = ("cancelled", "returned")   # এই অবস্থায় গেলে স্টক ফেরত আসে

DEFAULTS = {
    "shop_name": "BD SHOP", "tagline": "সেরা দামে সেরা পণ্য, দ্রুত ডেলিভারি",
    "brand": "#F05A28", "notice": "সারা দেশে ক্যাশ অন ডেলিভারি সুবিধা",
    "phone": "01740824851", "whatsapp": "01740824851", "email": "", "address": "",
    "ship_dhaka": "60", "ship_outside": "120", "free_over": "3000", "min_order": "0",
    "cod": "1", "bkash": "", "nagad": "", "pay_note": "", "tz": "6",
    "page_about": "এখানে আপনার দোকানের পরিচিতি লিখুন।\n\nঅ্যাডমিন প্যানেল > সেটিংস থেকে এই লেখা বদলানো যাবে।",
    "page_terms": "এখানে শর্তাবলি লিখুন।",
    "page_returns": "পণ্য হাতে পাওয়ার ৭ দিনের মধ্যে ত্রুটিপূর্ণ পণ্য ফেরত বা বদলানো যাবে।\n\nফেরতের জন্য আমাদের ফোনে যোগাযোগ করুন।",
    "page_privacy": "আপনার নাম, ফোন ও ঠিকানা শুধু অর্ডার পৌঁছে দেওয়ার কাজেই ব্যবহার করা হয়। তৃতীয় কারও কাছে বিক্রি বা শেয়ার করা হয় না।",
}
PUBLIC_KEYS = ["shop_name", "tagline", "brand", "notice", "phone", "whatsapp", "email", "address",
               "ship_dhaka", "ship_outside", "free_over", "min_order"]
INT_KEYS = ["ship_dhaka", "ship_outside", "free_over", "min_order", "tz"]
PAGE_KEYS = {"about": "page_about", "terms": "page_terms", "returns": "page_returns", "privacy": "page_privacy"}
PAGE_TITLES = {"about": "আমাদের সম্পর্কে", "terms": "শর্তাবলি", "returns": "ফেরত ও রিফান্ড নীতি", "privacy": "গোপনীয়তা নীতি"}
COMMON_PW = {"password", "password1", "12345678", "123456789", "1234567890", "qwertyuiop", "iloveyou1", "admin12345",
             "adminadmin", "letmein123", "welcome123", "abcd1234", "11111111", "00000000", "bangladesh", "dhaka12345"}


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


def now():
    return int(time.time())


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def ejson(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ==========================================================================
# ২. ডাটাবেস
# ==========================================================================
_local = threading.local()


def db():
    c = getattr(_local, "c", None)
    if c is None:
        c = sqlite3.connect(str(DB_PATH), timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=10000")
        _local.c = c
    return c


@contextlib.contextmanager
def tx():
    """একসাথে একটাই লেখার কাজ চলবে — স্টক ও অর্ডারে গোলমাল হয় না।"""
    c = db()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def rows(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]


def row(sql, args=()):
    r = db().execute(sql, args).fetchone()
    return dict(r) if r else None


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '🛍️',
  sort INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, title TEXT NOT NULL,
  category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
  price INTEGER NOT NULL, sale_price INTEGER, stock INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '', specs TEXT NOT NULL DEFAULT '',
  images TEXT NOT NULL DEFAULT '[]', variants TEXT NOT NULL DEFAULT '[]',
  featured INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
  sold INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_p_cat ON products(category_id, active);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, idem TEXT UNIQUE,
  name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL, district TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
  subtotal INTEGER NOT NULL, discount INTEGER NOT NULL DEFAULT 0, shipping INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL,
  coupon TEXT, payment TEXT NOT NULL, pay_ref TEXT NOT NULL DEFAULT '', pay_sender TEXT NOT NULL DEFAULT '',
  pay_status TEXT NOT NULL DEFAULT 'unpaid', status TEXT NOT NULL DEFAULT 'pending',
  created INTEGER NOT NULL, updated INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_o_status ON orders(status, created);
CREATE INDEX IF NOT EXISTS ix_o_phone ON orders(phone);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER, title TEXT NOT NULL, variant TEXT NOT NULL DEFAULT '', price INTEGER NOT NULL, qty INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS order_events(id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, value INTEGER NOT NULL,
  min_order INTEGER NOT NULL DEFAULT 0, max_uses INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
  expires INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS banners(id INTEGER PRIMARY KEY, title TEXT NOT NULL, subtitle TEXT NOT NULL DEFAULT '',
  link TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#F05A28',
  sort INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
  totp TEXT NOT NULL DEFAULT '', totp_on INTEGER NOT NULL DEFAULT 0, totp_last INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, last_login INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, csrf TEXT NOT NULL,
  created INTEGER NOT NULL, last INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '', ua TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, admin TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS throttle(key TEXT PRIMARY KEY, n INTEGER NOT NULL, first INTEGER NOT NULL, until INTEGER NOT NULL DEFAULT 0);
"""


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass
    db().executescript(SCHEMA)
    t = now() - 86400
    db().execute("DELETE FROM throttle WHERE until<? AND first<?", (t, t))
    db().execute("DELETE FROM sessions WHERE last<?", (now() - SESSION_MAX,))


def settings():
    d = dict(DEFAULTS)
    for r in db().execute("SELECT key,value FROM settings"):
        if r["key"] in d:
            d[r["key"]] = r["value"]
    return d


def audit(r, action, detail=""):
    who = r.sess["username"] if getattr(r, "sess", None) else ""
    db().execute("INSERT INTO audit(at,admin,action,detail,ip) VALUES(?,?,?,?,?)",
                 (now(), who, action, str(detail)[:300], r.client_ip()))


# ==========================================================================
# ৩. যাচাই সহায়ক
# ==========================================================================
def clean(v, mx, field, req=True, multiline=False):
    v = "" if v is None else str(v)
    v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)
    if not multiline:
        v = re.sub(r"[\r\n\t]+", " ", v)
    v = v.strip()
    if req and not v:
        raise ApiError("%s দিন" % field)
    if len(v) > mx:
        raise ApiError("%s সর্বোচ্চ %d অক্ষরের হতে পারে" % (field, mx))
    return v


def to_int(v, lo, hi, field):
    if isinstance(v, bool) or v is None or str(v).strip() == "":
        raise ApiError("%s দিন" % field)
    try:
        n = int(str(v).translate(BN).strip())
    except ValueError:
        raise ApiError("%s সংখ্যা হতে হবে" % field)
    if n < lo or n > hi:
        raise ApiError("%s %d থেকে %d এর মধ্যে হতে হবে" % (field, lo, hi))
    return n


def norm_phone(v):
    p = re.sub(r"[\s\-()]", "", str(v or "").translate(BN))
    if p.startswith("+880"):
        p = "0" + p[4:]
    elif p.startswith("880"):
        p = "0" + p[3:]
    if not re.fullmatch(r"01[3-9]\d{8}", p):
        raise ApiError("সঠিক মোবাইল নম্বর দিন (যেমন 01712345678)")
    return p


def is_hex(c):
    return isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c) is not None


def shade(hexc, f):
    n = int(hexc[1:], 16)
    r, g, b = (n >> 16) & 255, (n >> 8) & 255, n & 255
    r, g, b = [max(0, min(255, int(x * f))) for x in (r, g, b)]
    return "#%02x%02x%02x" % (r, g, b)


def lum(hexc):
    n = int(hexc[1:], 16)

    def f(v):
        v /= 255
        return v / 12.92 if v <= .03928 else ((v + .055) / 1.055) ** 2.4
    return .2126 * f((n >> 16) & 255) + .7152 * f((n >> 8) & 255) + .0722 * f(n & 255)


def like_pat(w):
    return "%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def check_pw(pw, username=""):
    """শক্ত পাসওয়ার্ড নীতি। ঠিক থাকলে None, নয়তো ভুলের বার্তা।"""
    if len(pw) < 10:
        return "পাসওয়ার্ড কমপক্ষে ১০ অক্ষরের হতে হবে"
    if len(pw) > 128:
        return "পাসওয়ার্ড খুব বড়"
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    need = 2 if len(pw) >= 16 else 3          # যথেষ্ট লম্বা হলে কম ধরনের অক্ষরেও চলবে (দৈর্ঘ্যই বড় সুরক্ষা)
    if classes < need:
        return "ছোট হাতের, বড় হাতের, সংখ্যা ও চিহ্ন — এর মধ্যে অন্তত %d ধরনের অক্ষর দিন (অথবা পাসওয়ার্ড আরও লম্বা করুন)" % need
    low = pw.lower()
    if low in COMMON_PW or (username and username.lower() in low) or len(set(pw)) < 5:
        return "এই পাসওয়ার্ড সহজে আন্দাজ করা যায়। অন্য একটি দিন"
    return None


# ==========================================================================
# ৪. পাসওয়ার্ড, TOTP, সেশন, থ্রটল
# ==========================================================================
def hash_pw(pw):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, salt.hex(), dk.hex())


def verify_pw(pw, stored):
    try:
        alg, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return alg == "pbkdf2_sha256" and hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


DUMMY_HASH = None   # ইউজার না থাকলেও একই সময় লাগানোর জন্য (timing attack ঠেকাতে)


def totp_code(secret, counter):
    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_verify(admin, code):
    code = re.sub(r"\D", "", str(code or "").translate(BN))
    if len(code) != 6 or not admin["totp"]:
        return False
    t = now() // 30
    for c in (t - 1, t, t + 1):
        if c > admin["totp_last"] and hmac.compare_digest(totp_code(admin["totp"], c), code):
            db().execute("UPDATE admins SET totp_last=? WHERE id=?", (c, admin["id"]))   # একই কোড দ্বিতীয়বার চলবে না
            return True
    return False


def th_locked(key):
    r = db().execute("SELECT until FROM throttle WHERE key=?", (key,)).fetchone()
    return max(0, r["until"] - now()) if r else 0


def th_fail(key, limit, window, lock):
    t = now()
    r = db().execute("SELECT n,first FROM throttle WHERE key=?", (key,)).fetchone()
    n, first = (r["n"] + 1, r["first"]) if r and t - r["first"] < window else (1, t)
    db().execute("INSERT OR REPLACE INTO throttle(key,n,first,until) VALUES(?,?,?,?)",
                 (key, n, first, t + lock if n >= limit else 0))


def th_clear(key):
    db().execute("DELETE FROM throttle WHERE key=?", (key,))


def th_allow(key, limit, window):
    """প্রতিটি চেষ্টা গুনে সীমা পার হলে false দেয় (অর্ডার/ট্র্যাক স্প্যাম ঠেকাতে)।"""
    t = now()
    r = db().execute("SELECT n,first FROM throttle WHERE key=?", (key,)).fetchone()
    n, first = (r["n"] + 1, r["first"]) if r and t - r["first"] < window else (1, t)
    db().execute("INSERT OR REPLACE INTO throttle(key,n,first,until) VALUES(?,?,?,0)", (key, n, first))
    return n <= limit


def new_session(admin_id, ip, ua):
    tok, csrf, t = secrets.token_urlsafe(32), secrets.token_urlsafe(24), now()
    db().execute("INSERT INTO sessions(token_hash,admin_id,csrf,created,last,ip,ua) VALUES(?,?,?,?,?,?,?)",
                 (sha(tok), admin_id, csrf, t, t, ip, ua[:200]))
    return tok, csrf


def get_session(tok):
    if not tok:
        return None
    r = db().execute("SELECT s.*, a.username, a.totp_on FROM sessions s JOIN admins a ON a.id=s.admin_id "
                     "WHERE s.token_hash=?", (sha(tok),)).fetchone()
    if not r:
        return None
    t = now()
    if t - r["last"] > SESSION_IDLE or t - r["created"] > SESSION_MAX:
        db().execute("DELETE FROM sessions WHERE id=?", (r["id"],))
        return None
    if t - r["last"] > 30:
        db().execute("UPDATE sessions SET last=? WHERE id=?", (t, r["id"]))
    return dict(r)


# ==========================================================================
# ৫. HTTP কাঠামো
# ==========================================================================
ROUTES = []


def route(method, pattern, admin=False):
    rx = re.compile(pattern)

    def deco(fn):
        ROUTES.append((method, rx, fn, admin))
        return fn
    return deco


class Resp:
    def __init__(self, body=b"", ctype="application/json; charset=utf-8", code=200, headers=None):
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.ctype, self.code, self.headers = ctype, code, headers or []


CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "Dokan"
    sess = None

    def log_message(self, fmt, *args):
        pass

    # ---- ক্লায়েন্টের তথ্য ----
    def peer_local(self):
        return self.client_address[0] in ("127.0.0.1", "::1")

    def client_ip(self):
        # Cloudflare/ngrok টানেল লোকাল থেকে আসে; তখনই শুধু forwarded হেডারে বিশ্বাস করি
        if self.peer_local():
            for h in ("CF-Connecting-IP", "X-Forwarded-For"):
                v = self.headers.get(h)
                if v:
                    return v.split(",")[0].strip()[:45]
        return self.client_address[0]

    def is_https(self):
        return self.peer_local() and self.headers.get("X-Forwarded-Proto", "") == "https"

    def cookie(self, name):
        try:
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return c[name].value if name in c else ""
        except Exception:
            return ""

    def check_origin(self):
        o = self.headers.get("Origin")
        if o and urlparse(o).netloc != self.headers.get("Host", ""):
            raise ApiError("অনুমোদিত নয়", 403)

    def body_bytes(self, limit):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > limit:
            raise ApiError("ডেটা খালি বা অতিরিক্ত বড়", 413)
        return self.rfile.read(n)

    def json(self):
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ApiError("Content-Type ঠিক নেই", 415)
        try:
            d = json.loads(self.body_bytes(MAX_JSON).decode("utf-8"))
        except ApiError:
            raise
        except Exception:
            raise ApiError("ডেটা পড়া যায়নি")
        if not isinstance(d, dict):
            raise ApiError("ডেটা ঠিক নেই")
        return d

    @property
    def q(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    # ---- বিতরণ ----
    def do_GET(self):
        self.handle_("GET")

    def do_POST(self):
        self.handle_("POST")

    def do_PUT(self):
        self.handle_("PUT")

    def do_DELETE(self):
        self.handle_("DELETE")

    def do_HEAD(self):
        self.handle_("GET")

    def handle_(self, method):
        try:
            resp = self.dispatch(method, urlparse(self.path).path)
        except ApiError as e:
            resp = Resp(ejson({"error": e.msg}), code=e.code)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            traceback.print_exc()
            resp = Resp(ejson({"error": "সার্ভারে একটি সমস্যা হয়েছে। একটু পরে আবার চেষ্টা করুন।"}), code=500)
        try:
            self.send_resp(resp)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def dispatch(self, method, p):
        if p.startswith("/static/"):
            return static_file(p[8:])
        if p.startswith("/uploads/"):
            return upload_file(p[9:])
        if p == "/robots.txt":
            return Resp("User-agent: *\nDisallow: /admin\nDisallow: /api\n", "text/plain; charset=utf-8")
        if p == "/sitemap.xml":
            return sitemap(self)
        if p in ("/admin", "/admin/"):
            return Resp(ADMIN_SHELL, "text/html; charset=utf-8",
                        headers=[("Content-Security-Policy", CSP), ("X-Robots-Tag", "noindex")])
        if p.startswith("/api/") or p.startswith("/admin/api/"):
            for m, rx, fn, adm in ROUTES:
                if m != method:
                    continue
                mo = rx.fullmatch(p)
                if not mo:
                    continue
                if method != "GET":
                    self.check_origin()
                if adm:
                    self.sess = get_session(self.cookie("dk_sid"))
                    if not self.sess:
                        raise ApiError("লগইন করুন", 401)
                    if method != "GET" and not hmac.compare_digest(self.headers.get("X-CSRF", ""), self.sess["csrf"]):
                        raise ApiError("নিরাপত্তা টোকেন মেলেনি। পেজ রিফ্রেশ করুন।", 403)
                out = fn(self, *mo.groups())
                if isinstance(out, Resp):
                    return out
                return Resp(ejson(out))
            raise ApiError("পাওয়া যায়নি", 404)
        if method == "GET":
            return storefront_shell(self, p)
        raise ApiError("পাওয়া যায়নি", 404)

    def send_resp(self, r):
        self.send_response(r.code)
        base = {"Content-Type": r.ctype, "Content-Length": str(len(r.body)), "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}
        for k, v in base.items():
            if not any(k.lower() == h[0].lower() for h in r.headers):
                self.send_header(k, v)
        for k, v in r.headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(r.body)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ==========================================================================
# ৬. স্ট্যাটিক ফাইল, শেল পাতা, ছবি
# ==========================================================================
ASSETS = {}


def register_assets(d):
    for name, (ctype, text) in d.items():
        b = text.encode("utf-8")
        ASSETS[name] = (ctype + "; charset=utf-8", b, hashlib.sha1(b).hexdigest()[:10])


def static_file(name):
    a = ASSETS.get(name)
    if not a:
        raise ApiError("পাওয়া যায়নি", 404)
    return Resp(a[1], a[0], headers=[("Cache-Control", "public, max-age=300"), ("ETag", '"%s"' % a[2])])


def asset_v(name):
    return ASSETS[name][2]


UP_RX = re.compile(r"[a-f0-9]{24}\.(jpg|png|gif|webp)")
UP_TYPES = {"jpg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp"}


def upload_file(name):
    if not UP_RX.fullmatch(name):
        raise ApiError("পাওয়া যায়নি", 404)
    f = UP_DIR / name
    if not f.is_file():
        raise ApiError("পাওয়া যায়নি", 404)
    return Resp(f.read_bytes(), UP_TYPES[name.rsplit(".", 1)[1]],
                headers=[("Cache-Control", "public, max-age=31536000, immutable"),
                         ("Content-Security-Policy", "default-src 'none'; sandbox")])


def sniff_image(b):
    if b[:3] == b"\xff\xd8\xff":
        return "jpg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:4] == b"GIF8":
        return "gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    return None


def drop_unused_images(files):
    """যে ছবি আর কোনো পণ্য/ব্যানারে নেই তা ডিস্ক থেকে মুছে ফেলে।"""
    for f in set(files):
        if not UP_RX.fullmatch(f):
            continue
        used = db().execute("SELECT 1 FROM products WHERE images LIKE ? UNION SELECT 1 FROM banners WHERE image=?",
                            ("%" + f + "%", f)).fetchone()
        if not used:
            try:
                (UP_DIR / f).unlink()
            except OSError:
                pass


SHELL = """<!doctype html><html lang="bn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{TITLE}</title><meta name="description" content="{DESC}">{OG}
<meta name="theme-color" content="{BRAND}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/store.css?v={V}">
<style>:root{{--brand:{BRAND};--brand-d:{BRAND_D};--on:{ON}}}</style></head>
<body><div id="root"></div><noscript><p style="padding:24px">এই সাইট চালাতে JavaScript চালু করুন।</p></noscript>
<script src="/static/store.js?v={V}"></script></body></html>"""

ADMIN_SHELL_TMPL = """<!doctype html><html lang="bn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>অ্যাডমিন প্যানেল</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/admin.css?v={V}"></head>
<body><div id="root"></div><noscript><p style="padding:24px">JavaScript চালু করুন।</p></noscript>
<script src="/static/admin.js?v={V}"></script></body></html>"""
ADMIN_SHELL = ""


def storefront_shell(r, path):
    S = settings()
    brand = S["brand"] if is_hex(S["brand"]) else DEFAULTS["brand"]
    name = S["shop_name"]
    title, desc, og = name + " — " + S["tagline"], S["tagline"], ""
    m = re.fullmatch(r"/p/(\d+)", path)
    if m:
        p = row(PSEL + " WHERE p.id=? AND p.active=1", (int(m.group(1)),))
        if p:
            pd = pdict(p, True)
            title = "%s — %s" % (pd["title"], name)
            desc = (pd["desc"] or S["tagline"]).replace("\n", " ")[:160]
            host = r.headers.get("Host", "localhost")
            proto = "https" if r.is_https() else "http"
            og = ('<meta property="og:title" content="%s"><meta property="og:description" content="%s">'
                  '<meta property="og:type" content="product">' % (html.escape(pd["title"]), html.escape(desc)))
            if pd["img"]:
                og += '<meta property="og:image" content="%s://%s/uploads/%s">' % (proto, html.escape(host), pd["img"])
    page = SHELL.format(TITLE=html.escape(title), DESC=html.escape(desc), OG=og, BRAND=brand, BRAND_D=shade(brand, .85),
                        ON="#111111" if lum(brand) > .35 else "#ffffff", V=asset_v("store.js") + asset_v("store.css"))
    return Resp(page, "text/html; charset=utf-8", headers=[("Content-Security-Policy", CSP)])


def sitemap(r):
    host = r.headers.get("Host", "localhost")
    proto = "https" if r.is_https() else "http"
    base = "%s://%s" % (proto, html.escape(host))
    urls = [base + "/"] + [base + "/shop?c=%d" % c["id"] for c in rows("SELECT id FROM categories WHERE active=1")]
    urls += [base + "/p/%d" % p["id"] for p in rows("SELECT id FROM products WHERE active=1 LIMIT 5000")]
    xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">%s</urlset>' % \
          "".join("<url><loc>%s</loc></url>" % u for u in urls)
    return Resp(xml, "application/xml; charset=utf-8")


# ==========================================================================
# ৭. পণ্য (দোকানের সামনের দিক)
# ==========================================================================
PSEL = "SELECT p.*, c.name AS cname, c.icon AS cicon FROM products p LEFT JOIN categories c ON c.id=p.category_id"
PRICE_EXPR = "CASE WHEN p.sale_price IS NOT NULL AND p.sale_price<p.price THEN p.sale_price ELSE p.price END"


def final_price(p):
    return p["sale_price"] if (p["sale_price"] and p["sale_price"] < p["price"]) else p["price"]


def pdict(p, full=False):
    vs = json.loads(p["variants"] or "[]")
    imgs = json.loads(p["images"] or "[]")
    base, fin = p["price"], final_price(p)
    sale = fin if fin < base else None
    d = {"id": p["id"], "title": p["title"], "price": base, "sale": sale, "final": fin,
         "off": round((base - fin) * 100 / base) if sale else 0, "img": imgs[0] if imgs else "",
         "stock": sum(v["stock"] for v in vs) if vs else p["stock"], "sold": p["sold"],
         "cat": p["category_id"], "catname": p.get("cname") or "", "icon": p.get("cicon") or "🛍️"}
    if full:
        specs = []
        for line in (p["specs"] or "").splitlines():
            k, _, v = line.partition(":")
            if k.strip() and v.strip():
                specs.append([k.strip(), v.strip()])
        d.update(images=imgs, desc=p["description"], specs=specs, created=p["created"],
                 variants=[{"label": v["label"], "price": v.get("price") or fin, "stock": v["stock"]} for v in vs])
    return d


def list_products(q, default_limit=20):
    w, a = ["p.active=1"], []
    c = q.get("c", "")
    if c.isdigit():
        w.append("p.category_id=?")
        a.append(int(c))
    if q.get("deal") == "1":
        w.append("p.sale_price IS NOT NULL AND p.sale_price<p.price")
    for word in (q.get("q") or "").split()[:5]:
        pat = like_pat(word[:40])
        w.append("(p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')")
        a += [pat, pat]
    if (q.get("min") or "").isdigit():
        w.append(PRICE_EXPR + ">=?")
        a.append(int(q["min"]))
    if (q.get("max") or "").isdigit():
        w.append(PRICE_EXPR + "<=?")
        a.append(int(q["max"]))
    order = {"new": "p.id DESC", "price_asc": PRICE_EXPR + " ASC, p.id DESC", "price_desc": PRICE_EXPR + " DESC, p.id DESC",
             "popular": "p.sold DESC, p.id DESC", "off": "(p.price-(" + PRICE_EXPR + ")) *100.0/p.price DESC, p.id DESC"
             }.get(q.get("sort", ""), "p.featured DESC, p.id DESC")
    where = " WHERE " + " AND ".join(w)
    total = db().execute("SELECT COUNT(*) FROM products p" + where, a).fetchone()[0]
    limit = min(int(q["limit"]), 40) if (q.get("limit") or "").isdigit() and int(q["limit"]) > 0 else default_limit
    pages = max(1, math.ceil(total / limit))
    page = min(max(int(q["page"]) if (q.get("page") or "").isdigit() else 1, 1), pages)
    items = rows(PSEL + where + " ORDER BY " + order + " LIMIT ? OFFSET ?", a + [limit, (page - 1) * limit])
    return {"items": [pdict(x) for x in items], "total": total, "page": page, "pages": pages}


def public_cfg():
    S = settings()
    return {"shop": {k: S[k] for k in PUBLIC_KEYS}, "districts": DISTRICTS,
            "categories": rows("SELECT id,name,icon FROM categories WHERE active=1 ORDER BY sort,id"),
            "pay": {"cod": S["cod"] == "1", "bkash": S["bkash"], "nagad": S["nagad"], "note": S["pay_note"]}}


@route("GET", r"/api/config")
def api_config(r):
    return public_cfg()


@route("GET", r"/api/home")
def api_home(r):
    def take(sql, n=12):
        return [pdict(x) for x in rows(PSEL + sql + " LIMIT %d" % n)]
    return {"banners": rows("SELECT id,title,subtitle,link,image,color FROM banners WHERE active=1 ORDER BY sort,id"),
            "categories": rows("SELECT id,name,icon FROM categories WHERE active=1 ORDER BY sort,id"),
            "deals": take(" WHERE p.active=1 AND p.sale_price IS NOT NULL AND p.sale_price<p.price "
                          "ORDER BY (p.price-p.sale_price)*100.0/p.price DESC"),
            "featured": take(" WHERE p.active=1 AND p.featured=1 ORDER BY p.id DESC"),
            "popular": take(" WHERE p.active=1 AND p.sold>0 ORDER BY p.sold DESC")}


@route("GET", r"/api/products")
def api_products(r):
    return list_products(r.q)


@route("GET", r"/api/suggest")
def api_suggest(r):
    w = (r.q.get("q") or "").strip()[:40]
    if len(w) < 2:
        return {"items": []}
    return {"items": rows("SELECT id,title FROM products WHERE active=1 AND title LIKE ? ESCAPE '\\' ORDER BY sold DESC LIMIT 6",
                          (like_pat(w),))}


@route("GET", r"/api/product/(\d+)")
def api_product(r, pid):
    p = row(PSEL + " WHERE p.id=? AND p.active=1", (int(pid),))
    if not p:
        raise ApiError("পণ্যটি পাওয়া যায়নি", 404)
    rel = []
    if p["category_id"]:
        rel = [pdict(x) for x in rows(PSEL + " WHERE p.active=1 AND p.category_id=? AND p.id<>? ORDER BY p.sold DESC, p.id DESC LIMIT 8",
                                      (p["category_id"], p["id"]))]
    return {"product": pdict(p, True), "related": rel}


@route("GET", r"/api/page/(\w+)")
def api_page(r, slug):
    if slug not in PAGE_KEYS:
        raise ApiError("পাওয়া যায়নি", 404)
    return {"title": PAGE_TITLES[slug], "body": settings()[PAGE_KEYS[slug]]}


# ---- কার্টের দাম/স্টক সার্ভারে যাচাই ----
def merge_items(raw):
    if not isinstance(raw, list) or not raw:
        raise ApiError("কার্ট খালি")
    if len(raw) > 40:
        raise ApiError("একসাথে অনেক বেশি পণ্য")
    out = {}
    for it in raw:
        if not isinstance(it, dict):
            raise ApiError("কার্টের তথ্য ঠিক নয়")
        pid = to_int(it.get("pid"), 1, 10 ** 9, "পণ্য")
        vid = clean(it.get("vid", ""), 60, "ভেরিয়েন্ট", False)
        qty = to_int(it.get("qty"), 1, 20, "পরিমাণ")
        k = (pid, vid)
        out[k] = min(20, out.get(k, 0) + qty)
    return [(k[0], k[1], q) for k, q in out.items()]


def line_price(p, vlabel):
    """(দাম, স্টক, ভেরিয়েন্টের লেবেল) দেয়; ভুল হলে (None, 0, বার্তা)।"""
    vs = json.loads(p["variants"] or "[]")
    fin = final_price(p)
    if vs:
        v = next((x for x in vs if x["label"] == vlabel), None)
        if not v:
            return None, 0, "ভেরিয়েন্ট বেছে নিন"
        return (v.get("price") or fin), v["stock"], ""
    return fin, p["stock"], ""


@route("POST", r"/api/cart")
def api_cart(r):
    d = r.json()
    lines = []
    for pid, vid, qty in merge_items(d.get("items")):
        p = row(PSEL + " WHERE p.id=? AND p.active=1", (pid,))
        if not p:
            lines.append({"pid": pid, "vid": vid, "qty": qty, "ok": False, "msg": "পণ্যটি আর পাওয়া যায় না", "title": "অনুপলব্ধ পণ্য"})
            continue
        price, stock, err = line_price(p, vid)
        imgs = json.loads(p["images"] or "[]")
        ln = {"pid": pid, "vid": vid, "qty": qty, "title": p["title"], "img": imgs[0] if imgs else "",
              "icon": p["cicon"] or "🛍️", "price": price or 0, "stock": stock, "ok": True, "msg": ""}
        if err:
            ln.update(ok=False, msg=err)
        elif stock <= 0:
            ln.update(ok=False, msg="স্টক শেষ")
        elif qty > stock:
            ln.update(qty=stock, msg="স্টকে আছে মাত্র %d টি" % stock)
        lines.append(ln)
    return {"lines": lines}


def coupon_discount(cp, subtotal):
    if not cp or not cp["active"]:
        raise ApiError("কুপন কোডটি সঠিক নয়")
    if cp["expires"] and now() > cp["expires"]:
        raise ApiError("কুপনটির মেয়াদ শেষ")
    if cp["max_uses"] and cp["used"] >= cp["max_uses"]:
        raise ApiError("কুপনটি আর ব্যবহার করা যাবে না")
    if subtotal < cp["min_order"]:
        raise ApiError("এই কুপনের জন্য কমপক্ষে ৳%d এর কেনাকাটা দরকার" % cp["min_order"])
    disc = subtotal * cp["value"] // 100 if cp["kind"] == "percent" else cp["value"]
    return max(0, min(disc, subtotal))


@route("POST", r"/api/coupon")
def api_coupon(r):
    if not th_allow("cp:" + r.client_ip(), 30, 600):
        raise ApiError("অনেক বেশি চেষ্টা। একটু পরে আবার দিন।", 429)
    d = r.json()
    code = clean(d.get("code"), 30, "কুপন কোড").upper()
    sub = to_int(d.get("subtotal"), 0, 10 ** 9, "মোট")
    cp = row("SELECT * FROM coupons WHERE code=?", (code,))
    return {"code": code, "discount": coupon_discount(cp, sub)}


# ==========================================================================
# ৮. অর্ডার তৈরি ও ট্র্যাকিং
# ==========================================================================
def order_public(o, items, events, S):
    return {"code": o["code"], "status": o["status"], "created": o["created"], "name": o["name"], "district": o["district"],
            "address": o["address"], "subtotal": o["subtotal"], "discount": o["discount"], "shipping": o["shipping"],
            "total": o["total"], "payment": o["payment"], "pay_status": o["pay_status"],
            "items": [{"title": i["title"], "variant": i["variant"], "price": i["price"], "qty": i["qty"]} for i in items],
            "events": [{"status": e["status"], "note": e["note"], "created": e["created"]} for e in events],
            "pay": {"bkash": S["bkash"], "nagad": S["nagad"]}}


@route("POST", r"/api/order")
def api_order(r):
    d = r.json()
    ip = r.client_ip()
    if d.get("hp"):                      # লুকানো ফাঁদ-ফিল্ড: বট হলে এখানে ধরা পড়ে
        raise ApiError("অনুরোধটি গ্রহণ করা যায়নি")
    if not th_allow("ord:" + ip, 12, 3600):
        raise ApiError("অনেক বেশি অর্ডার চেষ্টা হয়েছে। এক ঘণ্টা পরে আবার চেষ্টা করুন।", 429)
    S = settings()
    name = clean(d.get("name"), 80, "নাম")
    if len(name) < 2:
        raise ApiError("সঠিক নাম দিন")
    phone = norm_phone(d.get("phone"))
    district = d.get("district")
    if district not in DISTRICTS:
        raise ApiError("জেলা বেছে নিন")
    address = clean(d.get("address"), 300, "ঠিকানা")
    if len(address) < 8:
        raise ApiError("ঠিকানা আরও বিস্তারিত লিখুন (এলাকা, রাস্তা, বাড়ি নম্বর)")
    note = clean(d.get("note"), 300, "নোট", False)
    pay = d.get("payment")
    pay_ref = pay_sender = ""
    if pay == "cod" and S["cod"] == "1":
        pass
    elif pay in ("bkash", "nagad") and S[pay]:
        pay_ref = clean(d.get("pay_ref"), 20, "ট্রানজেকশন আইডি").upper()
        if not re.fullmatch(r"[A-Z0-9]{6,20}", pay_ref):
            raise ApiError("ট্রানজেকশন আইডি (TrxID) সঠিকভাবে দিন")
        pay_sender = norm_phone(d.get("pay_sender"))
    else:
        raise ApiError("পেমেন্ট পদ্ধতি বেছে নিন")
    items = merge_items(d.get("items"))
    idem = clean(d.get("idem"), 64, "", False) or None
    code_in = clean(d.get("coupon"), 30, "কুপন", False).upper()

    with tx() as c:
        if idem:
            ex = c.execute("SELECT code FROM orders WHERE idem=?", (idem,)).fetchone()
            if ex:                       # একই অর্ডার দুবার চাপলে পুরনোটাই ফেরত
                return {"code": ex["code"], "repeat": True}
        subtotal, lines = 0, []
        for pid, vid, qty in items:
            p = c.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
            if not p:
                raise ApiError("একটি পণ্য আর পাওয়া যাচ্ছে না। কার্ট ঠিক করে আবার চেষ্টা করুন।")
            p = dict(p)
            price, stock, err = line_price(p, vid)
            if err:
                raise ApiError('"%s": %s' % (p["title"], err))
            if stock < qty:
                raise ApiError('"%s" এর স্টকে আছে মাত্র %d টি' % (p["title"], max(stock, 0)))
            vs = json.loads(p["variants"] or "[]")
            if vs:
                for v in vs:
                    if v["label"] == vid:
                        v["stock"] -= qty
                c.execute("UPDATE products SET variants=?, sold=sold+? WHERE id=?", (json.dumps(vs, ensure_ascii=False), qty, pid))
            else:
                c.execute("UPDATE products SET stock=stock-?, sold=sold+? WHERE id=?", (qty, qty, pid))
            lines.append((pid, p["title"], vid, price, qty))
            subtotal += price * qty
        if subtotal < int(S["min_order"]):
            raise ApiError("সর্বনিম্ন অর্ডার ৳%s" % S["min_order"])
        disc, ccode = 0, None
        if code_in:
            cp = c.execute("SELECT * FROM coupons WHERE code=?", (code_in,)).fetchone()
            disc = coupon_discount(dict(cp) if cp else None, subtotal)
            c.execute("UPDATE coupons SET used=used+1 WHERE id=?", (cp["id"],))
            ccode = code_in
        ship = int(S["ship_dhaka"] if district == "ঢাকা" else S["ship_outside"])
        free = int(S["free_over"])
        if free > 0 and subtotal >= free:
            ship = 0
        total = subtotal - disc + ship
        t = now()
        for _ in range(8):
            code = "DK-" + "".join(secrets.choice(CODE_ALPHA) for _ in range(8))
            if not c.execute("SELECT 1 FROM orders WHERE code=?", (code,)).fetchone():
                break
        cur = c.execute("INSERT INTO orders(code,idem,name,phone,address,district,note,subtotal,discount,shipping,total,coupon,"
                        "payment,pay_ref,pay_sender,created,updated,ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (code, idem, name, phone, address, district, note, subtotal, disc, ship, total, ccode, pay,
                         pay_ref, pay_sender, t, t, ip))
        oid = cur.lastrowid
        for pid, title, vid, price, qty in lines:
            c.execute("INSERT INTO order_items(order_id,product_id,title,variant,price,qty) VALUES(?,?,?,?,?,?)",
                      (oid, pid, title, vid, price, qty))
        c.execute("INSERT INTO order_events(order_id,status,note,actor,created) VALUES(?,?,?,?,?)",
                  (oid, "pending", "অর্ডার গ্রহণ করা হয়েছে", "system", t))
    return {"code": code, "total": total}


@route("POST", r"/api/track")
def api_track(r):
    if not th_allow("trk:" + r.client_ip(), 20, 600):
        raise ApiError("অনেক বেশি চেষ্টা। কিছুক্ষণ পরে আবার দিন।", 429)
    d = r.json()
    code = clean(d.get("code"), 20, "অর্ডার কোড").upper()
    phone = norm_phone(d.get("phone"))
    o = row("SELECT * FROM orders WHERE code=?", (code,))
    if not o or o["phone"] != phone:
        raise ApiError("অর্ডার পাওয়া যায়নি। কোড ও ফোন নম্বর মিলিয়ে দেখুন।", 404)
    items = rows("SELECT * FROM order_items WHERE order_id=?", (o["id"],))
    events = rows("SELECT * FROM order_events WHERE order_id=? ORDER BY id", (o["id"],))
    return order_public(o, items, events, settings())


# ==========================================================================
# ৯. অ্যাডমিন: লগইন ও নিরাপত্তা
# ==========================================================================
def cookie_header(tok, r, clear=False):
    v = "dk_sid=%s; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=%d" % ("" if clear else tok, 0 if clear else SESSION_MAX)
    if r.is_https():
        v += "; Secure"
    return ("Set-Cookie", v)


@route("POST", r"/admin/api/login")
def admin_login(r):
    d = r.json()
    u = clean(d.get("username"), 64, "ইউজারনেম").lower()
    pw = str(d.get("password", ""))[:256]
    code = str(d.get("code", ""))[:12]
    ipk, uk = "lip:" + r.client_ip(), "lu:" + u
    for k in (ipk, uk):
        lk = th_locked(k)
        if lk:
            raise ApiError("অনেক ভুল চেষ্টা হয়েছে। %d মিনিট পরে আবার চেষ্টা করুন।" % math.ceil(lk / 60), 429)
    a = row("SELECT * FROM admins WHERE username=?", (u,))
    ok = verify_pw(pw, a["pw"] if a else DUMMY_HASH)
    if not (a and ok):
        th_fail(ipk, 10, 900, 900)
        th_fail(uk, 5, 900, 900)
        db().execute("INSERT INTO audit(at,admin,action,detail,ip) VALUES(?,?,?,?,?)",
                     (now(), u[:64], "login_failed", "", r.client_ip()))
        raise ApiError("ইউজারনেম বা পাসওয়ার্ড সঠিক নয়", 401)
    if a["totp_on"]:
        if not code.strip():
            return {"need_code": True}
        if not totp_verify(a, code):
            th_fail(ipk, 10, 900, 900)
            th_fail(uk, 5, 900, 900)
            raise ApiError("যাচাই কোড সঠিক নয়", 401)
    th_clear(uk)
    th_clear(ipk)
    tok, csrf = new_session(a["id"], r.client_ip(), r.headers.get("User-Agent", ""))
    db().execute("UPDATE admins SET last_login=? WHERE id=?", (now(), a["id"]))
    r.sess = {"username": u}
    audit(r, "login")
    return Resp(ejson({"ok": True, "csrf": csrf, "username": u, "totp_on": bool(a["totp_on"])}),
                headers=[cookie_header(tok, r)])


@route("POST", r"/admin/api/logout", admin=True)
def admin_logout(r):
    db().execute("DELETE FROM sessions WHERE id=?", (r.sess["id"],))
    audit(r, "logout")
    return Resp(ejson({"ok": True}), headers=[cookie_header("", r, True)])


@route("GET", r"/admin/api/me", admin=True)
def admin_me(r):
    return {"username": r.sess["username"], "csrf": r.sess["csrf"], "totp_on": bool(r.sess["totp_on"])}


@route("POST", r"/admin/api/password", admin=True)
def admin_password(r):
    d = r.json()
    a = row("SELECT * FROM admins WHERE id=?", (r.sess["admin_id"],))
    if not th_allow("pwchg:" + str(a["id"]), 8, 900):
        raise ApiError("অনেক বেশি চেষ্টা। একটু পরে আবার করুন।", 429)
    if not verify_pw(str(d.get("current", "")), a["pw"]):
        raise ApiError("বর্তমান পাসওয়ার্ড সঠিক নয়", 401)
    new = str(d.get("new", ""))
    msg = check_pw(new, a["username"])
    if msg:
        raise ApiError(msg)
    if verify_pw(new, a["pw"]):
        raise ApiError("নতুন পাসওয়ার্ড আগেরটির মতো হতে পারবে না")
    db().execute("UPDATE admins SET pw=? WHERE id=?", (hash_pw(new), a["id"]))
    db().execute("DELETE FROM sessions WHERE admin_id=? AND id<>?", (a["id"], r.sess["id"]))   # অন্য সব ডিভাইস লগআউট
    audit(r, "password_changed")
    return {"ok": True}


@route("POST", r"/admin/api/2fa/setup", admin=True)
def tfa_setup(r):
    secret = base64.b32encode(os.urandom(20)).decode()
    db().execute("UPDATE admins SET totp=?, totp_on=0, totp_last=0 WHERE id=?", (secret, r.sess["admin_id"]))
    shop = settings()["shop_name"]
    uri = "otpauth://totp/%s:%s?secret=%s&issuer=%s" % (quote(shop), quote(r.sess["username"]), secret, quote(shop))
    return {"secret": secret, "uri": uri}


@route("POST", r"/admin/api/2fa/enable", admin=True)
def tfa_enable(r):
    d = r.json()
    a = row("SELECT * FROM admins WHERE id=?", (r.sess["admin_id"],))
    if not a["totp"] or not th_allow("tfa:" + str(a["id"]), 8, 900) or not totp_verify(a, d.get("code")):
        raise ApiError("কোড সঠিক নয়। অ্যাপে দেখানো ৬ সংখ্যার কোডটি দিন।")
    db().execute("UPDATE admins SET totp_on=1 WHERE id=?", (a["id"],))
    audit(r, "2fa_enabled")
    return {"ok": True}


@route("POST", r"/admin/api/2fa/disable", admin=True)
def tfa_disable(r):
    d = r.json()
    a = row("SELECT * FROM admins WHERE id=?", (r.sess["admin_id"],))
    if not th_allow("tfa:" + str(a["id"]), 8, 900):
        raise ApiError("অনেক বেশি চেষ্টা", 429)
    if not verify_pw(str(d.get("password", "")), a["pw"]):
        raise ApiError("পাসওয়ার্ড সঠিক নয়", 401)
    db().execute("UPDATE admins SET totp='', totp_on=0, totp_last=0 WHERE id=?", (a["id"],))
    audit(r, "2fa_disabled")
    return {"ok": True}


@route("GET", r"/admin/api/sessions", admin=True)
def sessions_list(r):
    ss = rows("SELECT id,created,last,ip,ua FROM sessions WHERE admin_id=? ORDER BY last DESC", (r.sess["admin_id"],))
    for s in ss:
        s["current"] = s["id"] == r.sess["id"]
    return {"items": ss}


@route("POST", r"/admin/api/sessions/revoke", admin=True)
def sessions_revoke(r):
    db().execute("DELETE FROM sessions WHERE admin_id=? AND id<>?", (r.sess["admin_id"], r.sess["id"]))
    audit(r, "sessions_revoked")
    return {"ok": True}


@route("GET", r"/admin/api/audit", admin=True)
def audit_list(r):
    return {"items": rows("SELECT at,admin,action,detail,ip FROM audit ORDER BY id DESC LIMIT 80")}


# ==========================================================================
# ১০. অ্যাডমিন: ড্যাশবোর্ড ও অর্ডার
# ==========================================================================
def tzoff():
    try:
        return int(settings()["tz"]) * 3600
    except ValueError:
        return 6 * 3600


@route("GET", r"/admin/api/dashboard", admin=True)
def admin_dashboard(r):
    off, t = tzoff(), now()
    day0 = ((t + off) // 86400) * 86400 - off          # আজকের শুরু (স্থানীয় সময়ে)
    live = "status NOT IN ('cancelled','returned')"

    def agg(since):
        x = row("SELECT COUNT(*) n, COALESCE(SUM(total),0) s FROM orders WHERE %s AND created>=?" % live, (since,))
        return {"orders": x["n"], "revenue": x["s"]}
    series = []
    for i in range(13, -1, -1):
        s = day0 - i * 86400
        x = row("SELECT COUNT(*) n, COALESCE(SUM(total),0) s FROM orders WHERE %s AND created>=? AND created<?" % live, (s, s + 86400))
        series.append({"ts": s, "orders": x["n"], "revenue": x["s"]})
    return {
        "today": agg(day0), "week": agg(day0 - 6 * 86400), "month": agg(day0 - 29 * 86400),
        "pending": row("SELECT COUNT(*) n FROM orders WHERE status='pending'")["n"],
        "toship": row("SELECT COUNT(*) n FROM orders WHERE status IN ('confirmed','processing')")["n"],
        "products": row("SELECT COUNT(*) n FROM products WHERE active=1")["n"],
        "series": series,
        "recent": rows("SELECT id,code,name,total,status,created FROM orders ORDER BY id DESC LIMIT 8"),
        "top": rows("SELECT i.title, SUM(i.qty) q FROM order_items i JOIN orders o ON o.id=i.order_id "
                    "WHERE o.status NOT IN ('cancelled','returned') AND o.created>=? GROUP BY i.product_id, i.title "
                    "ORDER BY q DESC LIMIT 5", (day0 - 29 * 86400,)),
        "low": rows("SELECT id,title, CASE WHEN variants<>'[]' THEN -1 ELSE stock END AS stock FROM products "
                    "WHERE active=1 AND variants='[]' AND stock<=5 ORDER BY stock LIMIT 8"),
    }


@route("GET", r"/admin/api/poll", admin=True)
def admin_poll(r):
    x = row("SELECT COUNT(*) n, COALESCE(MAX(id),0) m FROM orders WHERE status='pending'")
    return {"pending": x["n"], "latest": row("SELECT COALESCE(MAX(id),0) m FROM orders")["m"]}


def order_filter(q):
    w, a = ["1=1"], []
    st = q.get("status", "")
    if st in FLOW:
        w.append("status=?")
        a.append(st)
    s = (q.get("q") or "").strip()[:40]
    if s:
        w.append("(code LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
        a += [like_pat(s.upper() if s.upper().startswith("DK-") else s)] * 3
    return " WHERE " + " AND ".join(w), a


@route("GET", r"/admin/api/orders", admin=True)
def admin_orders(r):
    where, a = order_filter(r.q)
    page = max(int(r.q["page"]) if (r.q.get("page") or "").isdigit() else 1, 1)
    per = 25
    total = db().execute("SELECT COUNT(*) FROM orders" + where, a).fetchone()[0]
    items = rows("SELECT id,code,name,phone,district,total,payment,pay_status,status,created FROM orders" + where +
                 " ORDER BY id DESC LIMIT ? OFFSET ?", a + [per, (page - 1) * per])
    counts = {x["status"]: x["n"] for x in rows("SELECT status, COUNT(*) n FROM orders GROUP BY status")}
    return {"items": items, "total": total, "page": page, "pages": max(1, math.ceil(total / per)), "counts": counts}


def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v      # স্প্রেডশিটে ফর্মুলা ইনজেকশন ঠেকাতে


@route("GET", r"/admin/api/orders\.csv", admin=True)
def admin_orders_csv(r):
    where, a = order_filter(r.q)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["অর্ডার", "তারিখ", "নাম", "ফোন", "জেলা", "ঠিকানা", "পণ্য", "সাবটোটাল", "ছাড়", "ডেলিভারি", "মোট",
                "পেমেন্ট", "TrxID", "পেমেন্ট অবস্থা", "অবস্থা"])
    off = tzoff()
    for o in rows("SELECT * FROM orders" + where + " ORDER BY id DESC LIMIT 5000", a):
        its = "; ".join("%s%s x%d" % (i["title"], " (%s)" % i["variant"] if i["variant"] else "", i["qty"])
                        for i in rows("SELECT * FROM order_items WHERE order_id=?", (o["id"],)))
        w.writerow([csv_safe(x) for x in (o["code"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(o["created"] + off)), o["name"],
                                          o["phone"], o["district"], o["address"], its, o["subtotal"], o["discount"],
                                          o["shipping"], o["total"], o["payment"], o["pay_ref"], o["pay_status"], o["status"])])
    audit(r, "orders_export")
    return Resp("\ufeff" + out.getvalue(), "text/csv; charset=utf-8",
                headers=[("Content-Disposition", 'attachment; filename="orders.csv"')])


@route("GET", r"/admin/api/orders/(\d+)", admin=True)
def admin_order(r, oid):
    o = row("SELECT * FROM orders WHERE id=?", (int(oid),))
    if not o:
        raise ApiError("অর্ডার পাওয়া যায়নি", 404)
    o["items"] = rows("SELECT * FROM order_items WHERE order_id=?", (o["id"],))
    o["events"] = rows("SELECT * FROM order_events WHERE order_id=? ORDER BY id", (o["id"],))
    o["next"] = FLOW[o["status"]]
    o["prev_orders"] = row("SELECT COUNT(*) n FROM orders WHERE phone=? AND id<>?", (o["phone"], o["id"]))["n"]
    return o


def restore_stock(c, oid):
    for it in c.execute("SELECT * FROM order_items WHERE order_id=?", (oid,)).fetchall():
        p = c.execute("SELECT * FROM products WHERE id=?", (it["product_id"],)).fetchone()
        if not p:
            continue
        vs = json.loads(p["variants"] or "[]")
        if vs:
            for v in vs:
                if v["label"] == it["variant"]:
                    v["stock"] += it["qty"]
            c.execute("UPDATE products SET variants=?, sold=MAX(0,sold-?) WHERE id=?",
                      (json.dumps(vs, ensure_ascii=False), it["qty"], p["id"]))
        else:
            c.execute("UPDATE products SET stock=stock+?, sold=MAX(0,sold-?) WHERE id=?", (it["qty"], it["qty"], p["id"]))
    if True:
        pass


@route("POST", r"/admin/api/orders/(\d+)/status", admin=True)
def admin_order_status(r, oid):
    d = r.json()
    new = d.get("status")
    note = clean(d.get("note"), 300, "নোট", False)
    with tx() as c:
        o = c.execute("SELECT * FROM orders WHERE id=?", (int(oid),)).fetchone()
        if not o:
            raise ApiError("অর্ডার পাওয়া যায়নি", 404)
        if new not in FLOW.get(o["status"], []):
            raise ApiError("এই অবস্থা থেকে সরাসরি ওই অবস্থায় যাওয়া যায় না")
        if new in STOCK_RESTORE:
            restore_stock(c, o["id"])
            if o["coupon"]:
                c.execute("UPDATE coupons SET used=MAX(0,used-1) WHERE code=?", (o["coupon"],))
        pay = "paid" if (new == "delivered" and o["payment"] == "cod") else o["pay_status"]
        c.execute("UPDATE orders SET status=?, pay_status=?, updated=? WHERE id=?", (new, pay, now(), o["id"]))
        c.execute("INSERT INTO order_events(order_id,status,note,actor,created) VALUES(?,?,?,?,?)",
                  (o["id"], new, note, r.sess["username"], now()))
    audit(r, "order_status", "%s -> %s" % (o["code"], new))
    return {"ok": True}


@route("POST", r"/admin/api/orders/(\d+)/pay", admin=True)
def admin_order_pay(r, oid):
    st = r.json().get("pay_status")
    if st not in ("paid", "unpaid"):
        raise ApiError("ঠিক নয়")
    n = db().execute("UPDATE orders SET pay_status=?, updated=? WHERE id=?", (st, now(), int(oid))).rowcount
    if not n:
        raise ApiError("অর্ডার পাওয়া যায়নি", 404)
    audit(r, "order_pay", "%s %s" % (oid, st))
    return {"ok": True}


# ==========================================================================
# ১১. অ্যাডমিন: পণ্য, ছবি
# ==========================================================================
@route("POST", r"/admin/api/upload", admin=True)
def admin_upload(r):
    ctype = r.headers.get("Content-Type", "")
    if not ctype.startswith("image/"):
        raise ApiError("শুধু ছবি আপলোড করা যাবে", 415)
    b = r.body_bytes(MAX_UPLOAD)
    ext = sniff_image(b)
    if not ext:
        raise ApiError("ছবিটি JPG, PNG, WEBP বা GIF হতে হবে")
    name = secrets.token_hex(12) + "." + ext
    (UP_DIR / name).write_bytes(b)
    return {"file": name}


def parse_product(d):
    title = clean(d.get("title"), 200, "পণ্যের নাম")
    if len(title) < 2:
        raise ApiError("পণ্যের নাম আরও লিখুন")
    price = to_int(d.get("price"), 1, 10 ** 8, "দাম")
    sale = None
    if str(d.get("sale_price", "")).strip() != "":
        sale = to_int(d.get("sale_price"), 1, 10 ** 8, "অফার দাম")
        if sale >= price:
            raise ApiError("অফার দাম আসল দামের চেয়ে কম হতে হবে")
    cat = None
    if str(d.get("category_id", "")).strip() not in ("", "0", "None"):
        cat = to_int(d.get("category_id"), 1, 10 ** 9, "ক্যাটাগরি")
        if not row("SELECT 1 FROM categories WHERE id=?", (cat,)):
            raise ApiError("ক্যাটাগরি পাওয়া যায়নি")
    desc = clean(d.get("description"), 6000, "বিবরণ", False, True)
    specs = clean(d.get("specs"), 3000, "বৈশিষ্ট্য", False, True)
    imgs = d.get("images") or []
    if not isinstance(imgs, list) or len(imgs) > 8:
        raise ApiError("সর্বোচ্চ ৮টি ছবি দেওয়া যায়")
    for f in imgs:
        if not isinstance(f, str) or not UP_RX.fullmatch(f) or not (UP_DIR / f).is_file():
            raise ApiError("ছবি ঠিক নেই, আবার আপলোড করুন")
    vs, seen = [], set()
    raw_vs = d.get("variants") or []
    if not isinstance(raw_vs, list) or len(raw_vs) > 40:
        raise ApiError("ভেরিয়েন্ট সর্বোচ্চ ৪০টি")
    for v in raw_vs:
        if not isinstance(v, dict):
            raise ApiError("ভেরিয়েন্ট ঠিক নয়")
        lab = clean(v.get("label"), 60, "ভেরিয়েন্টের নাম")
        if lab in seen:
            raise ApiError("ভেরিয়েন্টের নাম আলাদা হতে হবে")
        seen.add(lab)
        vp = None
        if str(v.get("price", "")).strip() != "":
            vp = to_int(v.get("price"), 1, 10 ** 8, "ভেরিয়েন্টের দাম")
        vs.append({"label": lab, "price": vp, "stock": to_int(v.get("stock", 0), 0, 10 ** 6, "ভেরিয়েন্টের স্টক")})
    stock = 0 if vs else to_int(d.get("stock", 0), 0, 10 ** 6, "স্টক")
    return (title, cat, price, sale, stock, desc, specs, json.dumps(imgs), json.dumps(vs, ensure_ascii=False),
            1 if d.get("featured") else 0, 1 if d.get("active", True) else 0)


@route("GET", r"/admin/api/products", admin=True)
def admin_products(r):
    w, a = ["1=1"], []
    s = (r.q.get("q") or "").strip()[:40]
    if s:
        w.append("p.title LIKE ? ESCAPE '\\'")
        a.append(like_pat(s))
    if r.q.get("low") == "1":
        w.append("p.variants='[]' AND p.stock<=5")
    page = max(int(r.q["page"]) if (r.q.get("page") or "").isdigit() else 1, 1)
    where = " WHERE " + " AND ".join(w)
    total = db().execute("SELECT COUNT(*) FROM products p" + where, a).fetchone()[0]
    items = rows(PSEL + where + " ORDER BY p.id DESC LIMIT 30 OFFSET ?", a + [(page - 1) * 30])
    out = []
    for p in items:
        d = pdict(p)
        d["active"] = p["active"]
        d["featured"] = p["featured"]
        d["has_variants"] = p["variants"] != "[]"
        out.append(d)
    return {"items": out, "total": total, "page": page, "pages": max(1, math.ceil(total / 30))}


@route("GET", r"/admin/api/products/(\d+)", admin=True)
def admin_product(r, pid):
    p = row("SELECT * FROM products WHERE id=?", (int(pid),))
    if not p:
        raise ApiError("পণ্য পাওয়া যায়নি", 404)
    p["images"] = json.loads(p["images"])
    p["variants"] = json.loads(p["variants"])
    return p


@route("POST", r"/admin/api/products", admin=True)
def admin_product_add(r):
    v = parse_product(r.json())
    cur = db().execute("INSERT INTO products(title,category_id,price,sale_price,stock,description,specs,images,variants,featured,"
                       "active,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", v + (now(),))
    audit(r, "product_add", v[0])
    return {"id": cur.lastrowid}


@route("PUT", r"/admin/api/products/(\d+)", admin=True)
def admin_product_edit(r, pid):
    old = row("SELECT images FROM products WHERE id=?", (int(pid),))
    if not old:
        raise ApiError("পণ্য পাওয়া যায়নি", 404)
    v = parse_product(r.json())
    db().execute("UPDATE products SET title=?,category_id=?,price=?,sale_price=?,stock=?,description=?,specs=?,images=?,variants=?,"
                 "featured=?,active=? WHERE id=?", v + (int(pid),))
    drop_unused_images(json.loads(old["images"]))
    audit(r, "product_edit", "%s %s" % (pid, v[0]))
    return {"ok": True}


@route("DELETE", r"/admin/api/products/(\d+)", admin=True)
def admin_product_del(r, pid):
    p = row("SELECT title,images FROM products WHERE id=?", (int(pid),))
    if not p:
        raise ApiError("পণ্য পাওয়া যায়নি", 404)
    if db().execute("SELECT 1 FROM order_items WHERE product_id=? LIMIT 1", (int(pid),)).fetchone():
        db().execute("UPDATE products SET active=0 WHERE id=?", (int(pid),))      # অর্ডারের ইতিহাস ঠিক রাখতে শুধু লুকানো হয়
        audit(r, "product_hide", p["title"])
        return {"ok": True, "hidden": True}
    db().execute("DELETE FROM products WHERE id=?", (int(pid),))
    drop_unused_images(json.loads(p["images"]))
    audit(r, "product_delete", p["title"])
    return {"ok": True}


# ==========================================================================
# ১২. অ্যাডমিন: ক্যাটাগরি, কুপন, ব্যানার, সেটিংস
# ==========================================================================
@route("GET", r"/admin/api/categories", admin=True)
def admin_cats(r):
    return {"items": rows("SELECT c.*, (SELECT COUNT(*) FROM products p WHERE p.category_id=c.id) AS n FROM categories c ORDER BY sort,id")}


def parse_cat(d):
    return (clean(d.get("name"), 40, "ক্যাটাগরির নাম"), clean(d.get("icon") or "🛍️", 8, "আইকন"),
            to_int(d.get("sort", 0), 0, 9999, "ক্রম"), 1 if d.get("active", True) else 0)


@route("POST", r"/admin/api/categories", admin=True)
def admin_cat_add(r):
    v = parse_cat(r.json())
    cur = db().execute("INSERT INTO categories(name,icon,sort,active) VALUES(?,?,?,?)", v)
    audit(r, "category_add", v[0])
    return {"id": cur.lastrowid}


@route("PUT", r"/admin/api/categories/(\d+)", admin=True)
def admin_cat_edit(r, cid):
    v = parse_cat(r.json())
    if not db().execute("UPDATE categories SET name=?,icon=?,sort=?,active=? WHERE id=?", v + (int(cid),)).rowcount:
        raise ApiError("পাওয়া যায়নি", 404)
    audit(r, "category_edit", v[0])
    return {"ok": True}


@route("DELETE", r"/admin/api/categories/(\d+)", admin=True)
def admin_cat_del(r, cid):
    db().execute("DELETE FROM categories WHERE id=?", (int(cid),))
    audit(r, "category_delete", cid)
    return {"ok": True}


def parse_expiry(v):
    v = str(v or "").strip()
    if not v:
        return 0
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v)
    if not m:
        raise ApiError("মেয়াদের তারিখ ঠিক নয়")
    try:
        return calendar.timegm((int(m[1]), int(m[2]), int(m[3]), 23, 59, 59)) - tzoff()
    except (ValueError, OverflowError):
        raise ApiError("মেয়াদের তারিখ ঠিক নয়")


def parse_coupon(d):
    code = clean(d.get("code"), 20, "কুপন কোড").upper()
    if not re.fullmatch(r"[A-Z0-9_-]{3,20}", code):
        raise ApiError("কোডে শুধু ইংরেজি অক্ষর, সংখ্যা, - বা _ (৩–২০ অক্ষর) দিন")
    kind = d.get("kind")
    if kind not in ("percent", "fixed"):
        raise ApiError("ধরন বেছে নিন")
    val = to_int(d.get("value"), 1, 90 if kind == "percent" else 1000000, "ছাড়ের পরিমাণ")
    return (code, kind, val, to_int(d.get("min_order", 0), 0, 10 ** 8, "সর্বনিম্ন অর্ডার"),
            to_int(d.get("max_uses", 0), 0, 10 ** 7, "ব্যবহারের সীমা"), parse_expiry(d.get("expires")),
            1 if d.get("active", True) else 0)


@route("GET", r"/admin/api/coupons", admin=True)
def admin_coupons(r):
    off = tzoff()
    items = rows("SELECT * FROM coupons ORDER BY id DESC")
    for c in items:
        c["expires"] = time.strftime("%Y-%m-%d", time.gmtime(c["expires"] + off)) if c["expires"] else ""
    return {"items": items}


@route("POST", r"/admin/api/coupons", admin=True)
def admin_coupon_add(r):
    v = parse_coupon(r.json())
    try:
        cur = db().execute("INSERT INTO coupons(code,kind,value,min_order,max_uses,expires,active) VALUES(?,?,?,?,?,?,?)", v)
    except sqlite3.IntegrityError:
        raise ApiError("এই কুপন কোড আগে থেকেই আছে")
    audit(r, "coupon_add", v[0])
    return {"id": cur.lastrowid}


@route("PUT", r"/admin/api/coupons/(\d+)", admin=True)
def admin_coupon_edit(r, cid):
    v = parse_coupon(r.json())
    try:
        n = db().execute("UPDATE coupons SET code=?,kind=?,value=?,min_order=?,max_uses=?,expires=?,active=? WHERE id=?",
                         v + (int(cid),)).rowcount
    except sqlite3.IntegrityError:
        raise ApiError("এই কুপন কোড আগে থেকেই আছে")
    if not n:
        raise ApiError("পাওয়া যায়নি", 404)
    audit(r, "coupon_edit", v[0])
    return {"ok": True}


@route("DELETE", r"/admin/api/coupons/(\d+)", admin=True)
def admin_coupon_del(r, cid):
    db().execute("DELETE FROM coupons WHERE id=?", (int(cid),))
    audit(r, "coupon_delete", cid)
    return {"ok": True}


def parse_banner(d):
    link = clean(d.get("link"), 200, "লিংক", False)
    if link and not (link.startswith("/") and not link.startswith("//")) and not link.startswith("https://"):
        raise ApiError("লিংক / দিয়ে (যেমন /shop?c=2) অথবা https:// দিয়ে শুরু হতে হবে")
    img = clean(d.get("image"), 60, "ছবি", False)
    if img and not (UP_RX.fullmatch(img) and (UP_DIR / img).is_file()):
        raise ApiError("ছবি ঠিক নেই")
    color = d.get("color") or "#F05A28"
    if not is_hex(color):
        raise ApiError("রং ঠিক নয়")
    return (clean(d.get("title"), 80, "শিরোনাম"), clean(d.get("subtitle"), 120, "উপশিরোনাম", False), link, img, color,
            to_int(d.get("sort", 0), 0, 9999, "ক্রম"), 1 if d.get("active", True) else 0)


@route("GET", r"/admin/api/banners", admin=True)
def admin_banners(r):
    return {"items": rows("SELECT * FROM banners ORDER BY sort,id")}


@route("POST", r"/admin/api/banners", admin=True)
def admin_banner_add(r):
    v = parse_banner(r.json())
    cur = db().execute("INSERT INTO banners(title,subtitle,link,image,color,sort,active) VALUES(?,?,?,?,?,?,?)", v)
    audit(r, "banner_add", v[0])
    return {"id": cur.lastrowid}


@route("PUT", r"/admin/api/banners/(\d+)", admin=True)
def admin_banner_edit(r, bid):
    old = row("SELECT image FROM banners WHERE id=?", (int(bid),))
    if not old:
        raise ApiError("পাওয়া যায়নি", 404)
    v = parse_banner(r.json())
    db().execute("UPDATE banners SET title=?,subtitle=?,link=?,image=?,color=?,sort=?,active=? WHERE id=?", v + (int(bid),))
    if old["image"] and old["image"] != v[3]:
        drop_unused_images([old["image"]])
    audit(r, "banner_edit", v[0])
    return {"ok": True}


@route("DELETE", r"/admin/api/banners/(\d+)", admin=True)
def admin_banner_del(r, bid):
    old = row("SELECT image FROM banners WHERE id=?", (int(bid),))
    db().execute("DELETE FROM banners WHERE id=?", (int(bid),))
    if old and old["image"]:
        drop_unused_images([old["image"]])
    audit(r, "banner_delete", bid)
    return {"ok": True}


@route("GET", r"/admin/api/settings", admin=True)
def admin_settings_get(r):
    return {"settings": settings(), "districts": DISTRICTS}


@route("PUT", r"/admin/api/settings", admin=True)
def admin_settings_put(r):
    d = r.json()
    out = {}
    for k in DEFAULTS:
        if k not in d:
            continue
        v = d[k]
        if k == "brand":
            if not is_hex(v):
                raise ApiError("ব্র্যান্ড রং ঠিক নয়")
            v = v.upper()
        elif k in INT_KEYS:
            v = str(to_int(v, -12 if k == "tz" else 0, 14 if k == "tz" else 10 ** 8, k))
        elif k == "cod":
            v = "1" if v in (1, "1", True) else "0"
        elif k in ("bkash", "nagad", "whatsapp"):
            v = norm_phone(v) if str(v).strip() else ""
        elif k.startswith("page_"):
            v = clean(v, 20000, "পেজ", False, True)
        else:
            v = clean(v, 300, k, False)
        out[k] = v
    if "shop_name" in out and not out["shop_name"]:
        raise ApiError("দোকানের নাম দিন")
    with tx() as c:
        for k, v in out.items():
            c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))
    audit(r, "settings_saved", ",".join(out))
    return {"ok": True}


# ==========================================================================
# ১৩. নমুনা তথ্য
# ==========================================================================
def seed_demo():
    if row("SELECT 1 FROM products LIMIT 1"):
        return
    cats = [("মোবাইল ও গ্যাজেট", "📱"), ("ফ্যাশন (পুরুষ)", "👔"), ("ফ্যাশন (নারী)", "👗"), ("ঘর ও কিচেন", "🏠"),
            ("সৌন্দর্য ও স্বাস্থ্য", "💄"), ("খেলনা ও শিশু", "🧸"), ("ইলেকট্রনিক্স", "🎧"), ("খাবার ও মুদি", "🛒")]
    ids = [db().execute("INSERT INTO categories(name,icon,sort) VALUES(?,?,?)", (n, i, k)).lastrowid for k, (n, i) in enumerate(cats)]
    P = [(0, "ওয়্যারলেস ব্লুটুথ ইয়ারবাড (ফাস্ট চার্জ)", 1850, 1290, 40, 1), (0, "১০০০০ mAh পাওয়ার ব্যাংক", 1600, 1350, 25, 0),
         (0, "স্মার্ট ওয়াচ (হার্ট রেট ও স্টেপ কাউন্টার)", 3200, 2450, 12, 1), (0, "ফোন কভার — প্রিমিয়াম সিলিকন", 450, 290, 80, 0),
         (1, "কটন পোলো টি-শার্ট", 750, 549, 0, 1), (1, "স্লিম ফিট চিনো প্যান্ট", 1450, 1190, 0, 0),
         (2, "ভিসকস থ্রি-পিস (আনস্টিচড)", 2400, 1890, 30, 1), (2, "হাতে বোনা শাড়ি", 3800, 3200, 9, 0),
         (3, "নন-স্টিক ফ্রাইপ্যান ২৬ সেমি", 1250, 890, 35, 1), (3, "ইলেকট্রিক কেটলি ১.৭ লিটার", 1650, 1390, 20, 0),
         (4, "ভিটামিন সি ফেস সিরাম ৩০ মি.লি.", 980, 720, 50, 1), (4, "হেয়ার ড্রায়ার ১২০০ ওয়াট", 1500, 1150, 15, 0),
         (5, "বাচ্চাদের বিল্ডিং ব্লক সেট (১০০ পিস)", 850, 620, 28, 0), (5, "রিমোট কন্ট্রোল রেসিং কার", 1350, 990, 18, 1),
         (6, "১৫ ইঞ্চি ল্যাপটপ ব্যাকপ্যাক", 1400, 1050, 22, 0), (6, "এলইডি টেবিল ল্যাম্প (রিচার্জেবল)", 780, 590, 45, 0),
         (7, "খাঁটি সরিষার তেল ৫ লিটার", 1150, 1090, 60, 0), (7, "প্রিমিয়াম মিনিকেট চাল ২৫ কেজি", 2050, None, 40, 1)]
    t = now()
    for ci, title, price, sale, stock, feat in P:
        vs = []
        if title.startswith("কটন পোলো"):
            vs = [{"label": s, "price": None, "stock": 10} for s in ("M", "L", "XL")]
        if title.startswith("স্লিম ফিট"):
            vs = [{"label": s, "price": None, "stock": 8} for s in ("৩০", "৩২", "৩৪")]
        db().execute("INSERT INTO products(title,category_id,price,sale_price,stock,description,specs,variants,featured,created) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (title, ids[ci], price, sale, 0 if vs else stock,
                      "এটি একটি নমুনা পণ্য। অ্যাডমিন প্যানেল থেকে আসল পণ্য, ছবি ও বিবরণ যোগ করুন।\n\nমান নিশ্চিত, দ্রুত ডেলিভারি।",
                      "ব্র্যান্ড: নমুনা\nওয়ারেন্টি: ৭ দিনের রিপ্লেসমেন্ট\nউৎপত্তি: দেশি/আমদানিকৃত", json.dumps(vs, ensure_ascii=False), feat, t))
    for i, (ti, su, li, co) in enumerate([("ঈদের মেগা অফার", "নির্বাচিত পণ্যে ৪০% পর্যন্ত ছাড়", "/shop?deal=1", "#F05A28"),
                                          ("নতুন কালেকশন", "ফ্যাশন ও লাইফস্টাইলে নতুন সব পণ্য", "/shop?sort=new", "#6D28D9"),
                                          ("ফ্রি ডেলিভারি", "৩০০০ টাকার ওপরে কেনাকাটায়", "/shop", "#0F766E")]):
        db().execute("INSERT INTO banners(title,subtitle,link,color,sort) VALUES(?,?,?,?,?)", (ti, su, li, co, i))
    db().execute("INSERT OR IGNORE INTO coupons(code,kind,value,min_order) VALUES('WELCOME10','percent',10,1000)")


# ==========================================================================
# ১৪. প্রথম চালু / কমান্ড লাইন
# ==========================================================================
def ask_password(username):
    while True:
        p1 = getpass.getpass("  নতুন পাসওয়ার্ড (লেখা দেখা যাবে না): ")
        msg = check_pw(p1, username)
        if msg:
            print("  ✗ " + msg)
            continue
        if getpass.getpass("  আবার লিখুন: ") != p1:
            print("  ✗ দুটো মেলেনি, আবার দিন")
            continue
        return p1


def setup_admin(reset=False, cli_user=None, cli_pass=None):
    tty = sys.stdin.isatty()
    if reset:
        print("\n  অ্যাডমিন পাসওয়ার্ড রিসেট (২-ধাপ যাচাইও বন্ধ হবে, সব সেশন লগআউট হবে)")
    else:
        print("\n  প্রথমবার চালু হচ্ছে — অ্যাডমিন অ্যাকাউন্ট বানান (কোনো ডিফল্ট পাসওয়ার্ড নেই)")
    if cli_user or cli_pass:
        u = (cli_user or "admin").strip().lower()
        msg = check_pw(cli_pass or "", u)
        if msg:
            sys.exit("  ✗ " + msg)
        pw = cli_pass
        print("  --admin-user/--admin-pass থেকে অ্যাডমিন সেট করা হচ্ছে")
    elif tty:
        u = (input("  অ্যাডমিন ইউজারনেম [admin]: ").strip() or "admin").lower()
        pw = ask_password(u)
    else:
        u = "admin"
        pw = "".join(secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(16)) + "#7"
        print("  অটো পাসওয়ার্ড তৈরি হলো (এখনই লিখে রাখুন, আর দেখানো হবে না):\n    ইউজারনেম: %s\n    পাসওয়ার্ড: %s" % (u, pw))
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", u):
        sys.exit("  ইউজারনেমে শুধু ইংরেজি ছোট অক্ষর, সংখ্যা, . _ - (৩–৩২ অক্ষর) থাকতে পারে")
    h = hash_pw(pw)
    ex = row("SELECT id FROM admins WHERE username=?", (u,))
    if ex:
        db().execute("UPDATE admins SET pw=?, totp='', totp_on=0, totp_last=0 WHERE id=?", (h, ex["id"]))
        db().execute("DELETE FROM sessions WHERE admin_id=?", (ex["id"],))
    else:
        db().execute("INSERT INTO admins(username,pw,created) VALUES(?,?,?)", (u, h, now()))
    db().execute("INSERT INTO audit(at,admin,action,detail,ip) VALUES(?,?,?,?,?)", (now(), u, "cli_admin_set", "", "local"))
    print("  ✓ অ্যাডমিন প্রস্তুত: %s\n" % u)


def do_backup():
    init_db()
    stamp = time.strftime("%Y%m%d-%H%M")
    tmp = DATA_DIR / "backup-tmp.db"
    if tmp.exists():
        tmp.unlink()
    dst = sqlite3.connect(str(tmp))
    db().backup(dst)
    dst.close()
    out = Path.home() / ("dokan-backup-%s.tar.gz" % stamp)
    with tarfile.open(out, "w:gz") as tf:
        tf.add(tmp, arcname="shop.db")
        tf.add(UP_DIR, arcname="uploads")
    tmp.unlink()
    print("ব্যাকআপ তৈরি হয়েছে: %s" % out)


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def main():
    global DUMMY_HASH, ADMIN_SHELL
    ap = argparse.ArgumentParser(description="দোকান — ই-কমার্স ওয়েবসাইট")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    ap.add_argument("--lan", action="store_true", help="একই Wi-Fi-র অন্য ডিভাইস থেকেও খুলতে দিন")
    ap.add_argument("--demo", action="store_true", help="নমুনা পণ্য, ক্যাটাগরি ও ব্যানার যোগ করুন")
    ap.add_argument("--reset-admin", action="store_true", help="অ্যাডমিন পাসওয়ার্ড রিসেট")
    ap.add_argument("--admin-user", default=None, help="অ্যাডমিন ইউজারনেম সরাসরি সেট করুন (ইন্টারেক্টিভ প্রশ্ন ছাড়াই)")
    ap.add_argument("--admin-pass", default=None, help="অ্যাডমিন পাসওয়ার্ড সরাসরি সেট করুন (ইন্টারেক্টিভ প্রশ্ন ছাড়াই)")
    ap.add_argument("--backup", action="store_true", help="ব্যাকআপ তৈরি করে বেরিয়ে যান")
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()

    register_assets({"store.css": ("text/css", STORE_CSS), "store.js": ("application/javascript", STORE_JS),
                     "admin.css": ("text/css", ADMIN_CSS), "admin.js": ("application/javascript", ADMIN_JS)})
    ADMIN_SHELL = ADMIN_SHELL_TMPL.replace("{V}", asset_v("admin.js") + asset_v("admin.css"))
    if a.backup:
        return do_backup()
    init_db()
    DUMMY_HASH = hash_pw(secrets.token_hex(8))
    if a.reset_admin:
        setup_admin(True, a.admin_user, a.admin_pass)
        return
    if not row("SELECT 1 FROM admins LIMIT 1"):
        setup_admin(False, a.admin_user, a.admin_pass)
    elif a.admin_user or a.admin_pass:
        print("  ℹ️  অ্যাডমিন আগে থেকেই আছে। পাসওয়ার্ড বদলাতে --reset-admin ব্যবহার করুন।")
    if a.demo:
        seed_demo()
        print("  ✓ নমুনা তথ্য যোগ হয়েছে (কুপন: WELCOME10)")

    host = "0.0.0.0" if a.lan else "127.0.0.1"
    srv, port = None, a.port
    for p in range(a.port, a.port + 10):
        try:
            srv = Server((host, p), Handler)
            port = p
            break
        except OSError:
            continue
    if not srv:
        sys.exit("পোর্ট %d–%d ব্যস্ত। --port দিয়ে অন্য পোর্ট দিন।" % (a.port, a.port + 9))
    print("=" * 56)
    print("  দোকান চালু হয়েছে")
    print("=" * 56)
    print("  দোকান          : http://127.0.0.1:%d/" % port)
    print("  অ্যাডমিন প্যানেল : http://127.0.0.1:%d/admin" % port)
    if a.lan and lan_ip():
        print("  অন্য ডিভাইসে   : http://%s:%d/" % (lan_ip(), port))
    print("  ডেটা থাকে      : %s" % DATA_DIR)
    print("  বন্ধ করতে      : Ctrl + C")
    print("=" * 56)
    if not a.no_open and shutil.which("termux-open-url"):
        try:
            subprocess.Popen(["termux-open-url", "http://127.0.0.1:%d/" % port], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nবন্ধ করা হলো।")
    finally:
        srv.server_close()


# ==========================================================================
# ১৫. ফ্রন্টএন্ড ফাইল (এগুলো build.py নিজে বসায়)
# ==========================================================================
def _b64(s):
    return base64.b64decode(s).decode("utf-8")


STORE_CSS = _b64("LyogPT09PT0g4Kat4Ka/4Kak4KeN4Kak4Ka/ID09PT09ICovCip7Ym94LXNpemluZzpib3JkZXItYm94fQpodG1sLGJvZHl7bWFyZ2luOjA7cGFkZGluZzowfQpib2R5e2JhY2tncm91bmQ6dmFyKC0tYmcsI0YzRjRGOCk7Y29sb3I6dmFyKC0tdHgsIzE2MUEyRSk7Zm9udDo0MDAgMTVweC8xLjYgJ0hpbmQgU2lsaWd1cmknLHN5c3RlbS11aSwtYXBwbGUtc3lzdGVtLCdTZWdvZSBVSScsc2Fucy1zZXJpZjstd2Via2l0LXRhcC1oaWdobGlnaHQtY29sb3I6dHJhbnNwYXJlbnR9Cjpyb290ey0tYmc6I0YzRjRGODstLXM6I2ZmZjstLXMyOiNGMEYxRjc7LS1sbjojRTRFNkYwOy0tdHg6IzE2MUEyRTstLW11OiM2QjcwODY7LS1vazojMEU4QTVGOy0tYmFkOiNEMjI2NEE7LS1yOjE0cHh9CmltZ3ttYXgtd2lkdGg6MTAwJTtkaXNwbGF5OmJsb2NrfQphe2NvbG9yOmluaGVyaXQ7dGV4dC1kZWNvcmF0aW9uOm5vbmV9CmJ1dHRvbixpbnB1dCxzZWxlY3QsdGV4dGFyZWF7Zm9udDppbmhlcml0O2NvbG9yOmluaGVyaXR9CmJ1dHRvbntjdXJzb3I6cG9pbnRlcn0KOmZvY3VzLXZpc2libGV7b3V0bGluZToycHggc29saWQgdmFyKC0tYnJhbmQpO291dGxpbmUtb2Zmc2V0OjJweH0KLndyYXB7bWF4LXdpZHRoOjExODBweDttYXJnaW46MCBhdXRvO3BhZGRpbmc6MCAxNHB4fQouc3J7cG9zaXRpb246YWJzb2x1dGU7d2lkdGg6MXB4O2hlaWdodDoxcHg7b3ZlcmZsb3c6aGlkZGVuO2NsaXA6cmVjdCgwLDAsMCwwKX0KOjotd2Via2l0LXNjcm9sbGJhcntoZWlnaHQ6NnB4O3dpZHRoOjZweH0KOjotd2Via2l0LXNjcm9sbGJhci10aHVtYntiYWNrZ3JvdW5kOnZhcigtLWxuKTtib3JkZXItcmFkaXVzOjZweH0KCi8qID09PT09IOCmn+CmqiDgpqzgpr7gprAgPT09PT0gKi8KLnRvcGJhcntiYWNrZ3JvdW5kOnZhcigtLWJyYW5kLWQpO2NvbG9yOiNmZmY7Zm9udC1zaXplOjEyLjVweDt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjZweCAxMHB4fQouaGRye3Bvc2l0aW9uOnN0aWNreTt0b3A6MDt6LWluZGV4OjMwO2JhY2tncm91bmQ6dmFyKC0tcyk7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbG4pfQouaGRyLWlue2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7aGVpZ2h0OjU4cHh9Ci5sb2dve2ZvbnQ6NzAwIDIwcHggJ0hpbmQgU2lsaWd1cmknO2NvbG9yOnZhcigtLWJyYW5kLWQpO3doaXRlLXNwYWNlOm5vd3JhcDtmbGV4Om5vbmV9Ci5zZWFyY2hiYXJ7ZmxleDoxO3Bvc2l0aW9uOnJlbGF0aXZlO2Rpc3BsYXk6ZmxleH0KLnNlYXJjaGJhciBpbnB1dHt3aWR0aDoxMDAlO2JvcmRlcjoxLjVweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweCA0MHB4IDEwcHggMTRweDtiYWNrZ3JvdW5kOnZhcigtLXMyKX0KLnNlYXJjaGJhciBpbnB1dDpmb2N1c3tib3JkZXItY29sb3I6dmFyKC0tYnJhbmQpO2JhY2tncm91bmQ6dmFyKC0tcyl9Ci5zZWFyY2hiYXIgYnV0dG9ue3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0OjJweDt0b3A6MnB4O2JvdHRvbToycHg7d2lkdGg6NDBweDtiYWNrZ3JvdW5kOnZhcigtLWJyYW5kKTtjb2xvcjp2YXIoLS1vbik7Ym9yZGVyOjA7Ym9yZGVyLXJhZGl1czo4cHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyfQouc3VnZ2VzdHtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6Y2FsYygxMDAlICsgNnB4KTtsZWZ0OjA7cmlnaHQ6MDtiYWNrZ3JvdW5kOnZhcigtLXMpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6MTJweDtib3gtc2hhZG93OjAgMTJweCAyOHB4IHJnYmEoMjAsMjAsNDAsLjEyKTtvdmVyZmxvdzpoaWRkZW47ei1pbmRleDo0MH0KLnN1Z2dlc3QgYnV0dG9ue2Rpc3BsYXk6YmxvY2s7d2lkdGg6MTAwJTt0ZXh0LWFsaWduOnJpZ2h0O3BhZGRpbmc6MTFweCAxNHB4O2JvcmRlcjowO2JhY2tncm91bmQ6bm9uZTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1sbik7Zm9udC1zaXplOjE0LjVweH0KLnN1Z2dlc3QgYnV0dG9uOmxhc3QtY2hpbGR7Ym9yZGVyLWJvdHRvbTowfQouc3VnZ2VzdCBidXR0b246aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1zMil9Ci5oaWNvbnN7ZGlzcGxheTpmbGV4O2dhcDo0cHg7ZmxleDpub25lfQouaGljb257cG9zaXRpb246cmVsYXRpdmU7d2lkdGg6NDBweDtoZWlnaHQ6NDBweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Ym9yZGVyLXJhZGl1czoxMHB4O2ZsZXg6bm9uZX0KLmhpY29uOmhvdmVye2JhY2tncm91bmQ6dmFyKC0tczIpfQouaGljb24gc3Zne3dpZHRoOjIycHg7aGVpZ2h0OjIycHg7ZmlsbDpub25lO3N0cm9rZTpjdXJyZW50Q29sb3I7c3Ryb2tlLXdpZHRoOjEuODtzdHJva2UtbGluZWNhcDpyb3VuZDtzdHJva2UtbGluZWpvaW46cm91bmR9Ci5iYWRnZXtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MXB4O3JpZ2h0OjFweDtiYWNrZ3JvdW5kOnZhcigtLWJyYW5kKTtjb2xvcjp2YXIoLS1vbik7Zm9udC1zaXplOjEwcHg7Zm9udC13ZWlnaHQ6NzAwO21pbi13aWR0aDoxNnB4O2hlaWdodDoxNnB4O2JvcmRlci1yYWRpdXM6OHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtwYWRkaW5nOjAgM3B4fQouY2F0YmFye292ZXJmbG93LXg6YXV0bzt3aGl0ZS1zcGFjZTpub3dyYXA7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0tbG4pO3Njcm9sbGJhci13aWR0aDpub25lO2Rpc3BsYXk6bm9uZX0KLmNhdGJhcjo6LXdlYmtpdC1zY3JvbGxiYXJ7ZGlzcGxheTpub25lfQouY2F0YmFyIC53cmFwe2Rpc3BsYXk6ZmxleDtnYXA6NnB4O3BhZGRpbmc6OHB4IDE0cHh9Ci5jYXRiYXIgYXtmbGV4Om5vbmU7cGFkZGluZzo3cHggMTRweDtib3JkZXItcmFkaXVzOjk5OXB4O2JhY2tncm91bmQ6dmFyKC0tczIpO2ZvbnQtc2l6ZToxMy41cHh9Ci5jYXRiYXIgYS5vbntiYWNrZ3JvdW5kOnZhcigtLWJyYW5kKTtjb2xvcjp2YXIoLS1vbil9CkBtZWRpYShtaW4td2lkdGg6NzYwcHgpey5jYXRiYXJ7ZGlzcGxheTpibG9ja319CgovKiA9PT09PSDgprngpr/gprDgp4sgLyDgpqzgp43gpq/gpr7gpqjgpr7gprAgPT09PT0gKi8KLmhlcm97cGFkZGluZzoxNHB4IDAgNHB4fQouaHNsaWRle3Bvc2l0aW9uOnJlbGF0aXZlO2JvcmRlci1yYWRpdXM6MTZweDtvdmVyZmxvdzpoaWRkZW47bWluLWhlaWdodDoxNTBweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2NvbG9yOiNmZmZ9Ci5oc2xpZGUgaW1ne3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7d2lkdGg6MTAwJTtoZWlnaHQ6MTAwJTtvYmplY3QtZml0OmNvdmVyO3otaW5kZXg6MH0KLmhzbGlkZTo6YmVmb3Jle2NvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6MDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMDBkZWcscmdiYSgwLDAsMCwuNTUpLHJnYmEoMCwwLDAsLjA1KSl9Ci5oc2xpZGUgLmlue3Bvc2l0aW9uOnJlbGF0aXZlO3BhZGRpbmc6MjZweCAyMnB4O21heC13aWR0aDo3MCV9Ci5oc2xpZGUgaDJ7Zm9udC1zaXplOmNsYW1wKDE4cHgsMy40dncsMjhweCk7bWFyZ2luOjAgMCA2cHh9Ci5oc2xpZGUgcHttYXJnaW46MDtvcGFjaXR5Oi45Mjtmb250LXNpemU6MTMuNXB4fQouaGRvdHN7ZGlzcGxheTpmbGV4O2dhcDo2cHg7anVzdGlmeS1jb250ZW50OmNlbnRlcjttYXJnaW4tdG9wOjEwcHh9Ci5oZG90cyBpe3dpZHRoOjdweDtoZWlnaHQ6N3B4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6dmFyKC0tbG4pfQouaGRvdHMgaS5vbntiYWNrZ3JvdW5kOnZhcigtLWJyYW5kKX0KCi8qID09PT09IOCmuOCnh+CmleCmtuCmqCDgppXgpq7gpqggPT09PT0gKi8KLnNlY3twYWRkaW5nOjIycHggMH0KLnNlYy1oe2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpiYXNlbGluZTtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjttYXJnaW4tYm90dG9tOjEycHh9Ci5zZWMtaCBoMntmb250LXNpemU6MThweDttYXJnaW46MDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHh9Ci5zZWMtaCBhe2ZvbnQtc2l6ZToxM3B4O2NvbG9yOnZhcigtLWJyYW5kLWQpO2ZvbnQtd2VpZ2h0OjYwMH0KLm5vdGljZXtiYWNrZ3JvdW5kOnZhcigtLXMyKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxMHB4IDE0cHg7Zm9udC1zaXplOjEzLjVweDtjb2xvcjp2YXIoLS1tdSk7bWFyZ2luOjEwcHggMH0KCi8qID09PT09IOCmleCnjeCmr+CmvuCmn+CmvuCml+CmsOCmvyDgppfgp43gprDgpr/gpqEgPT09PT0gKi8KLmNhdGdyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpO2dhcDoxMHB4fQouY2F0Y2FyZHtiYWNrZ3JvdW5kOnZhcigtLXMpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6MTRweDtwYWRkaW5nOjE0cHggNnB4O3RleHQtYWxpZ246Y2VudGVyO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjZweDthbGlnbi1pdGVtczpjZW50ZXJ9Ci5jYXRjYXJkIC5pY3tmb250LXNpemU6MjZweH0KLmNhdGNhcmQgc3Bhbntmb250LXNpemU6MTJweDtsaW5lLWhlaWdodDoxLjN9CkBtZWRpYShtaW4td2lkdGg6NjAwcHgpey5jYXRncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNiwxZnIpfX0KQG1lZGlhKG1pbi13aWR0aDo5MDBweCl7LmNhdGdyaWR7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCg4LDFmcil9fQoKLyogPT09PT0g4Kaq4Kaj4KeN4KavIOCml+CnjeCmsOCmv+CmoSA9PT09PSAqLwoucGdyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpO2dhcDoxMXB4fQpAbWVkaWEobWluLXdpZHRoOjU2MHB4KXsucGdyaWR7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcil9fQpAbWVkaWEobWluLXdpZHRoOjgyMHB4KXsucGdyaWR7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCg0LDFmcil9fQpAbWVkaWEobWluLXdpZHRoOjEwODBweCl7LnBncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNSwxZnIpfX0KLnBncmlkLnJvd3tkaXNwbGF5OmZsZXg7Z2FwOjExcHg7b3ZlcmZsb3cteDphdXRvO3Njcm9sbC1zbmFwLXR5cGU6eCBtYW5kYXRvcnk7cGFkZGluZy1ib3R0b206NHB4O3Njcm9sbGJhci13aWR0aDpub25lfQoucGdyaWQucm93Ojotd2Via2l0LXNjcm9sbGJhcntkaXNwbGF5Om5vbmV9Ci5wZ3JpZC5yb3c+KntmbGV4OjAgMCAxNDhweDtzY3JvbGwtc25hcC1hbGlnbjpzdGFydH0KLnBjYXJke2JhY2tncm91bmQ6dmFyKC0tcyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czoxNHB4O292ZXJmbG93OmhpZGRlbjtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO3Bvc2l0aW9uOnJlbGF0aXZlO3RyYW5zaXRpb246Ym94LXNoYWRvdyAuMTVzLHRyYW5zZm9ybSAuMTVzfQoucGNhcmQ6aG92ZXJ7Ym94LXNoYWRvdzowIDEwcHggMjRweCByZ2JhKDIwLDIwLDQwLC4xMCk7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoLTJweCl9Ci5waW1ne2FzcGVjdC1yYXRpbzoxLzE7YmFja2dyb3VuZDp2YXIoLS1zMikgY2VudGVyL2NvdmVyIG5vLXJlcGVhdDtwb3NpdGlvbjpyZWxhdGl2ZTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjM0cHh9Ci5wb2Zme3Bvc2l0aW9uOmFic29sdXRlO3RvcDo4cHg7bGVmdDo4cHg7YmFja2dyb3VuZDp2YXIoLS1iYWQpO2NvbG9yOiNmZmY7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwO3BhZGRpbmc6MnB4IDdweDtib3JkZXItcmFkaXVzOjZweH0KLnBzb2xke3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LC43Mik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS1iYWQpO2ZvbnQtc2l6ZToxM3B4fQoucGJvZHl7cGFkZGluZzo5cHggMTBweCAxMXB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjVweDtmbGV4OjF9Ci5wdGl0bGV7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS40O21pbi1oZWlnaHQ6Mi43ZW07b3ZlcmZsb3c6aGlkZGVuO2Rpc3BsYXk6LXdlYmtpdC1ib3g7LXdlYmtpdC1saW5lLWNsYW1wOjI7LXdlYmtpdC1ib3gtb3JpZW50OnZlcnRpY2FsfQoucHByaWNle2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpiYXNlbGluZTtnYXA6NnB4O21hcmdpbi10b3A6YXV0b30KLnBwcmljZSBie2ZvbnQtc2l6ZToxNS41cHg7Y29sb3I6dmFyKC0tYnJhbmQtZCl9Ci5wcHJpY2Ugc3tjb2xvcjp2YXIoLS1tdSk7Zm9udC1zaXplOjEycHh9Ci5wc29sZC1saW5le2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11KX0KLnBhZGRidG57bWFyZ2luLXRvcDo0cHg7YmFja2dyb3VuZDp2YXIoLS1icmFuZCk7Y29sb3I6dmFyKC0tb24pO2JvcmRlcjowO2JvcmRlci1yYWRpdXM6OHB4O3BhZGRpbmc6N3B4O2ZvbnQtc2l6ZToxMi41cHg7Zm9udC13ZWlnaHQ6NzAwO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtnYXA6NXB4fQoucGFkZGJ0bjpkaXNhYmxlZHtiYWNrZ3JvdW5kOnZhcigtLWxuKTtjb2xvcjp2YXIoLS1tdSl9CgovKiA9PT09PSDgpqvgpr/gprLgp43gpp/gpr7gprAv4Ka24KaqIOCmquCmvuCmpOCmviA9PT09PSAqLwouc2hvcGhlYWR7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDo4cHg7YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbi1ib3R0b206MTRweH0KLmNoaXB7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxuKTtib3JkZXItcmFkaXVzOjk5OXB4O3BhZGRpbmc6N3B4IDEzcHg7Zm9udC1zaXplOjEzcHh9Ci5jaGlwLm9ue2JhY2tncm91bmQ6dmFyKC0tYnJhbmQpO2NvbG9yOnZhcigtLW9uKTtib3JkZXItY29sb3I6dmFyKC0tYnJhbmQpfQpzZWxlY3Quc29ydHNlbHtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxuKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzo4cHggMTBweDtiYWNrZ3JvdW5kOnZhcigtLXMpO21hcmdpbi1sZWZ0OmF1dG99Ci5lbXB0eXt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjUwcHggMjBweDtjb2xvcjp2YXIoLS1tdSl9Ci5wYWdlcntkaXNwbGF5OmZsZXg7Z2FwOjZweDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO21hcmdpbi10b3A6MjBweDtmbGV4LXdyYXA6d3JhcH0KLnBhZ2VyIGJ1dHRvbnt3aWR0aDozNnB4O2hlaWdodDozNnB4O2JvcmRlci1yYWRpdXM6OXB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbG4pO2JhY2tncm91bmQ6dmFyKC0tcyl9Ci5wYWdlciBidXR0b24ub257YmFja2dyb3VuZDp2YXIoLS1icmFuZCk7Y29sb3I6dmFyKC0tb24pO2JvcmRlci1jb2xvcjp2YXIoLS1icmFuZCl9CgovKiA9PT09PSDgpqrgpqPgp43gpq/gp4fgprAg4Kaq4Ka+4Kak4Ka+ID09PT09ICovCi5wZHZpZXd7ZGlzcGxheTpncmlkO2dhcDoyMnB4O3BhZGRpbmc6MTZweCAwfQpAbWVkaWEobWluLXdpZHRoOjg0MHB4KXsucGR2aWV3e2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyfX0KLmdhbC1tYWlue2FzcGVjdC1yYXRpbzoxLzE7Ym9yZGVyLXJhZGl1czoxNnB4O292ZXJmbG93OmhpZGRlbjtiYWNrZ3JvdW5kOnZhcigtLXMyKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjYwcHh9Ci5nYWwtdGh1bWJze2Rpc3BsYXk6ZmxleDtnYXA6OHB4O21hcmdpbi10b3A6OHB4O292ZXJmbG93LXg6YXV0b30KLmdhbC10aHVtYnMgaW1ne3dpZHRoOjYwcHg7aGVpZ2h0OjYwcHg7b2JqZWN0LWZpdDpjb3Zlcjtib3JkZXItcmFkaXVzOjlweDtib3JkZXI6MnB4IHNvbGlkIHRyYW5zcGFyZW50O2ZsZXg6bm9uZX0KLmdhbC10aHVtYnMgaW1nLm9ue2JvcmRlci1jb2xvcjp2YXIoLS1icmFuZCl9Ci5wZC10aXRsZXtmb250LXNpemU6Y2xhbXAoMTlweCwzdncsMjVweCk7bWFyZ2luOjAgMCA4cHh9Ci5wZC1tZXRhe2NvbG9yOnZhcigtLW11KTtmb250LXNpemU6MTNweDttYXJnaW4tYm90dG9tOjEycHh9Ci5wZC1wcmljZXtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6YmFzZWxpbmU7Z2FwOjEwcHg7bWFyZ2luOjEwcHggMH0KLnBkLXByaWNlIGJ7Zm9udC1zaXplOjI2cHg7Y29sb3I6dmFyKC0tYnJhbmQtZCl9Ci5wZC1wcmljZSBze2NvbG9yOnZhcigtLW11KX0KLnBkLW9mZntiYWNrZ3JvdW5kOiNGREVDRUY7Y29sb3I6dmFyKC0tYmFkKTtmb250LXdlaWdodDo3MDA7Zm9udC1zaXplOjEyLjVweDtwYWRkaW5nOjJweCA4cHg7Ym9yZGVyLXJhZGl1czo2cHh9Ci52cm93e2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6OHB4O21hcmdpbjoxMHB4IDB9Ci52Y2hpcHtib3JkZXI6MS41cHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OHB4IDE0cHg7Zm9udC1zaXplOjEzLjVweDtiYWNrZ3JvdW5kOnZhcigtLXMpfQoudmNoaXAub257Ym9yZGVyLWNvbG9yOnZhcigtLWJyYW5kKTtiYWNrZ3JvdW5kOiNGRkY0RUU7Y29sb3I6dmFyKC0tYnJhbmQtZCk7Zm9udC13ZWlnaHQ6NzAwfQoudmNoaXA6ZGlzYWJsZWR7b3BhY2l0eTouNDt0ZXh0LWRlY29yYXRpb246bGluZS10aHJvdWdofQoucXR5cm93e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjA7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czoxMHB4O3dpZHRoOmZpdC1jb250ZW50O21hcmdpbjoxMnB4IDB9Ci5xdHlyb3cgYnV0dG9ue3dpZHRoOjM4cHg7aGVpZ2h0OjM4cHg7YmFja2dyb3VuZDpub25lO2JvcmRlcjowO2ZvbnQtc2l6ZToxN3B4fQoucXR5cm93IHNwYW57d2lkdGg6MzhweDt0ZXh0LWFsaWduOmNlbnRlcjtmb250LXdlaWdodDo3MDB9Ci5wZC1hY3Rze2Rpc3BsYXk6ZmxleDtnYXA6MTBweDttYXJnaW4tdG9wOjE0cHg7ZmxleC13cmFwOndyYXB9Ci5idG57YmFja2dyb3VuZDp2YXIoLS1icmFuZCk7Y29sb3I6dmFyKC0tb24pO2JvcmRlcjowO2JvcmRlci1yYWRpdXM6MTFweDtwYWRkaW5nOjEzcHggMjJweDtmb250LXdlaWdodDo3MDA7Zm9udC1zaXplOjE0LjVweDt0ZXh0LWFsaWduOmNlbnRlcn0KLmJ0bi5iaWd7ZmxleDoxO21pbi13aWR0aDoxNjBweH0KLmJ0bi5naG9zdHtiYWNrZ3JvdW5kOnZhcigtLXMpO2JvcmRlcjoxLjVweCBzb2xpZCB2YXIoLS1icmFuZCk7Y29sb3I6dmFyKC0tYnJhbmQtZCl9Ci5idG4uYmxvY2t7ZGlzcGxheTpibG9jazt3aWR0aDoxMDAlfQouYnRuOmRpc2FibGVke2JhY2tncm91bmQ6dmFyKC0tbG4pO2NvbG9yOnZhcigtLW11KTtjdXJzb3I6bm90LWFsbG93ZWR9Ci5zdG9ja2xpbmV7Zm9udC1zaXplOjEzcHg7bWFyZ2luOjZweCAwfQouc3RvY2tsaW5lLm9re2NvbG9yOnZhcigtLW9rKX0KLnN0b2NrbGluZS5sb3d7Y29sb3I6dmFyKC0tYmFkKX0KLnRhYnMye2Rpc3BsYXk6ZmxleDtnYXA6NnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWxuKTttYXJnaW46MjJweCAwIDB9Ci50YWJzMiBidXR0b257cGFkZGluZzoxMXB4IDRweDtib3JkZXI6MDtiYWNrZ3JvdW5kOm5vbmU7Zm9udC13ZWlnaHQ6NjAwO2NvbG9yOnZhcigtLW11KTtib3JkZXItYm90dG9tOjJweCBzb2xpZCB0cmFuc3BhcmVudDttYXJnaW4tcmlnaHQ6MThweH0KLnRhYnMyIGJ1dHRvbi5vbntjb2xvcjp2YXIoLS1icmFuZC1kKTtib3JkZXItY29sb3I6dmFyKC0tYnJhbmQpfQoucGQtZGVzY3t3aGl0ZS1zcGFjZTpwcmUtd3JhcDtsaW5lLWhlaWdodDoxLjg1O3BhZGRpbmc6MTZweCAwO2NvbG9yOnZhcigtLXR4KX0KLnNwZWN0YWJsZXt3aWR0aDoxMDAlO2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtmb250LXNpemU6MTRweH0KLnNwZWN0YWJsZSB0ZHtwYWRkaW5nOjlweCA0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbG4pfQouc3BlY3RhYmxlIHRkOmZpcnN0LWNoaWxke2NvbG9yOnZhcigtLW11KTt3aWR0aDozOCV9Ci50cnVzdHJvd3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjE0cHg7bWFyZ2luLXRvcDoxNnB4O2ZvbnQtc2l6ZToxMi41cHg7Y29sb3I6dmFyKC0tbXUpfQoudHJ1c3Ryb3cgc3BhbntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHh9CgovKiA9PT09PSDgppXgpr7gprDgp43gpp8g4Kah4KeN4Kaw4Kav4Ka84Ka+4KawID09PT09ICovCi5vdmVybGF5e3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7YmFja2dyb3VuZDpyZ2JhKDEwLDEwLDIwLC40NSk7ei1pbmRleDo2MDtvcGFjaXR5OjA7cG9pbnRlci1ldmVudHM6bm9uZTt0cmFuc2l0aW9uOm9wYWNpdHkgLjJzfQoub3ZlcmxheS5vbntvcGFjaXR5OjE7cG9pbnRlci1ldmVudHM6YXV0b30KLmRyYXdlcntwb3NpdGlvbjpmaXhlZDt0b3A6MDtyaWdodDowO2JvdHRvbTowO3dpZHRoOm1pbig0MjBweCw5MnZ3KTtiYWNrZ3JvdW5kOnZhcigtLXMpO3otaW5kZXg6NjE7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoMTAwJSk7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjI1cztkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1ufQouZHJhd2VyLm9ue3RyYW5zZm9ybTp0cmFuc2xhdGVYKDApfQouZHItaGR7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweDtwYWRkaW5nOjE2cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbG4pfQouZHItaGQgaDN7bWFyZ2luOjA7ZmxleDoxO2ZvbnQtc2l6ZToxN3B4fQouZHItY2xvc2V7d2lkdGg6MzRweDtoZWlnaHQ6MzRweDtib3JkZXItcmFkaXVzOjlweDtiYWNrZ3JvdW5kOnZhcigtLXMyKTtib3JkZXI6MDtmb250LXNpemU6MTZweH0KLmRyLWJvZHl7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwYWRkaW5nOjEycHggMTZweH0KLmNpdGVte2Rpc3BsYXk6ZmxleDtnYXA6MTBweDtwYWRkaW5nOjExcHggMDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1sbil9Ci5jaXRlbSBpbWcsLmNpdGVtIC5pYzJ7d2lkdGg6NjBweDtoZWlnaHQ6NjBweDtib3JkZXItcmFkaXVzOjlweDtvYmplY3QtZml0OmNvdmVyO2JhY2tncm91bmQ6dmFyKC0tczIpO2ZsZXg6bm9uZTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjI0cHh9Ci5jaXRlbSAuY2ktYntmbGV4OjE7bWluLXdpZHRoOjB9Ci5jaXRlbSAuY2ktdHtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjQ7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXM7ZGlzcGxheTotd2Via2l0LWJveDstd2Via2l0LWxpbmUtY2xhbXA6Mjstd2Via2l0LWJveC1vcmllbnQ6dmVydGljYWx9Ci5jaXRlbSAuY2ktdntmb250LXNpemU6MTEuNXB4O2NvbG9yOnZhcigtLW11KX0KLmNpdGVtIC5jaS13YXJue2ZvbnQtc2l6ZToxMS41cHg7Y29sb3I6dmFyKC0tYmFkKTttYXJnaW4tdG9wOjJweH0KLmNpLXF0eXtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7bWFyZ2luLXRvcDo2cHh9Ci5jaS1xdHkgYnV0dG9ue3dpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo3cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7YmFja2dyb3VuZDp2YXIoLS1zKX0KLmNpLXByaWNle2ZvbnQtd2VpZ2h0OjcwMDtmb250LXNpemU6MTMuNXB4O3doaXRlLXNwYWNlOm5vd3JhcH0KLmNpLXJte2NvbG9yOnZhcigtLW11KTtmb250LXNpemU6MTJweDttYXJnaW4tdG9wOjRweDt0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lfQouZHItZm9vdHtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1sbik7cGFkZGluZzoxNHB4IDE2cHg7cGFkZGluZy1ib3R0b206Y2FsYygxNHB4ICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKX0KLnN1bXJvd3tkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Zm9udC1zaXplOjEzLjVweDtwYWRkaW5nOjNweCAwO2NvbG9yOnZhcigtLW11KX0KLnN1bXJvdy50b3R7Zm9udC1zaXplOjE2LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgpO2JvcmRlci10b3A6MXB4IGRhc2hlZCB2YXIoLS1sbik7bWFyZ2luLXRvcDo2cHg7cGFkZGluZy10b3A6OXB4fQouY2FydGVtcHR5e3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6NjBweCAxNnB4O2NvbG9yOnZhcigtLW11KX0KCi8qID09PT09IOCmmuCnh+CmleCmhuCmieCmnyA9PT09PSAqLwouY2t3cmFwe2Rpc3BsYXk6Z3JpZDtnYXA6MjJweDtwYWRkaW5nOjE2cHggMH0KQG1lZGlhKG1pbi13aWR0aDo5MDBweCl7LmNrd3JhcHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MS4yZnIgLjhmcjthbGlnbi1pdGVtczpzdGFydH19Ci5jYXJke2JhY2tncm91bmQ6dmFyKC0tcyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MThweH0KLmNhcmQrLmNhcmR7bWFyZ2luLXRvcDoxNHB4fQouY2FyZCBoM3ttYXJnaW46MCAwIDEycHg7Zm9udC1zaXplOjE2cHh9Ci5me2Rpc3BsYXk6Z3JpZDtnYXA6NXB4O21hcmdpbi1ib3R0b206MTNweH0KLmY+c3Bhbntmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1tdSl9Ci5mIGlucHV0LC5mIHNlbGVjdCwuZiB0ZXh0YXJlYXtib3JkZXI6MS41cHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjExcHggMTJweDtiYWNrZ3JvdW5kOnZhcigtLXMyKX0KLmYgaW5wdXQ6Zm9jdXMsLmYgc2VsZWN0OmZvY3VzLC5mIHRleHRhcmVhOmZvY3Vze2JhY2tncm91bmQ6dmFyKC0tcyk7Ym9yZGVyLWNvbG9yOnZhcigtLWJyYW5kKX0KLmYgdGV4dGFyZWF7bWluLWhlaWdodDo3MHB4O3Jlc2l6ZTp2ZXJ0aWNhbH0KLmYtZXJye2JvcmRlci1jb2xvcjp2YXIoLS1iYWQpIWltcG9ydGFudH0KLmVycnRleHR7Y29sb3I6dmFyKC0tYmFkKTtmb250LXNpemU6MTJweH0KLmYye2Rpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyIDFmcjtnYXA6MTJweH0KLnBheW9wdHtib3JkZXI6MS41cHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEycHggMTRweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O21hcmdpbi1ib3R0b206OXB4O2N1cnNvcjpwb2ludGVyfQoucGF5b3B0Lm9ue2JvcmRlci1jb2xvcjp2YXIoLS1icmFuZCk7YmFja2dyb3VuZDojRkZGNkYwfQoucGF5b3B0IGlucHV0e2FjY2VudC1jb2xvcjp2YXIoLS1icmFuZCl9Ci5wYXlvcHQgYntmb250LXNpemU6MTRweH0KLnBheW9wdCBzbWFsbHtkaXNwbGF5OmJsb2NrO2NvbG9yOnZhcigtLW11KTtmb250LXNpemU6MTJweH0KLmNvdXBvbnJvd3tkaXNwbGF5OmZsZXg7Z2FwOjhweH0KLmNvdXBvbnJvdyBpbnB1dHtmbGV4OjF9Ci5ob25leXBvdHtwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0Oi05OTk5cHg7d2lkdGg6MXB4O2hlaWdodDoxcHg7b3ZlcmZsb3c6aGlkZGVufQouc3RpY2t5YmFye3Bvc2l0aW9uOnN0aWNreTtib3R0b206MDtiYWNrZ3JvdW5kOnZhcigtLXMpO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWxuKTtwYWRkaW5nOjEycHggMTRweDtwYWRkaW5nLWJvdHRvbTpjYWxjKDEycHggKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEycHg7ei1pbmRleDoxMH0KLnN0aWNreWJhciBie2ZvbnQtc2l6ZToxN3B4O2NvbG9yOnZhcigtLWJyYW5kLWQpfQoKLyogPT09PT0g4Kaf4KeN4Kaw4KeN4Kav4Ka+4KaV4Ka/4KaCIC8g4Ka44Ka+4Kar4Kay4KeN4KavID09PT09ICovCi5jZW50ZXItYm94e21heC13aWR0aDo0ODBweDttYXJnaW46NDBweCBhdXRvO3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6MCAxNnB4fQoub2tpY29ue3dpZHRoOjcwcHg7aGVpZ2h0OjcwcHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDojRThGOEYxO2NvbG9yOnZhcigtLW9rKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7bWFyZ2luOjAgYXV0byAxNnB4O2ZvbnQtc2l6ZTozNHB4fQouY29kZWJveHtiYWNrZ3JvdW5kOnZhcigtLXMyKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxNHB4O2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxcHg7bWFyZ2luOjE0cHggMH0KLnRpbWVsaW5le2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjA7bWFyZ2luOjIwcHggMH0KLnRsLWl0ZW17ZGlzcGxheTpmbGV4O2dhcDoxMnB4O3Bvc2l0aW9uOnJlbGF0aXZlO3BhZGRpbmctYm90dG9tOjIycHh9Ci50bC1pdGVtOmxhc3QtY2hpbGR7cGFkZGluZy1ib3R0b206MH0KLnRsLWRvdHt3aWR0aDoxMnB4O2hlaWdodDoxMnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6dmFyKC0tbG4pO2ZsZXg6bm9uZTttYXJnaW4tdG9wOjRweDtwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjF9Ci50bC1pdGVtLmRvbmUgLnRsLWRvdHtiYWNrZ3JvdW5kOnZhcigtLW9rKX0KLnRsLWl0ZW06bm90KDpsYXN0LWNoaWxkKTo6YmVmb3Jle2NvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7bGVmdDo1LjVweDt0b3A6MTZweDtib3R0b206MDt3aWR0aDoxLjVweDtiYWNrZ3JvdW5kOnZhcigtLWxuKX0KLnRsLWJ7dGV4dC1hbGlnbjpyaWdodDtmbGV4OjF9Ci50bC1iIGJ7ZGlzcGxheTpibG9jaztmb250LXNpemU6MTRweH0KLnRsLWIgc21hbGx7Y29sb3I6dmFyKC0tbXUpO2ZvbnQtc2l6ZToxMnB4fQoKLyogPT09PT0g4Ka54KeL4Kav4Ka84Ka+4Kaf4Ka44KaF4KeN4Kav4Ka+4KaqIOCmq+CnjeCmsuCni+Cmn+Cmv+CmgiDgpqzgpr7gpp/gpqggPT09PT0gKi8KLndhLWZsb2F0e3Bvc2l0aW9uOmZpeGVkO3JpZ2h0OjE2cHg7Ym90dG9tOjc4cHg7d2lkdGg6NTRweDtoZWlnaHQ6NTRweDtib3JkZXItcmFkaXVzOjUwJTtiYWNrZ3JvdW5kOiMyNUQzNjY7Y29sb3I6I2ZmZjtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Ym94LXNoYWRvdzowIDhweCAyMHB4IHJnYmEoMzcsMjExLDEwMiwuNDUpO3otaW5kZXg6MzQ7YW5pbWF0aW9uOndhcHVsc2UgMi40cyBlYXNlIGluZmluaXRlfQoud2EtZmxvYXQgc3Zne3dpZHRoOjI4cHg7aGVpZ2h0OjI4cHh9CkBrZXlmcmFtZXMgd2FwdWxzZXswJSwxMDAle3RyYW5zZm9ybTpzY2FsZSgxKX01MCV7dHJhbnNmb3JtOnNjYWxlKDEuMDYpfX0KQG1lZGlhKG1pbi13aWR0aDo5MDBweCl7LndhLWZsb2F0e2JvdHRvbToyNHB4fX0KCi8qID09PT09IOCmq+CngeCmn+CmvuCmsCA9PT09PSAqLwouZm9vdHtiYWNrZ3JvdW5kOiMxNTFBMkU7Y29sb3I6I0I2QkJENjttYXJnaW4tdG9wOjM2cHg7cGFkZGluZzozNnB4IDAgMjBweH0KLmZvb3QgLndyYXB7ZGlzcGxheTpncmlkO2dhcDoyNnB4O2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9CkBtZWRpYShtaW4td2lkdGg6NzAwcHgpey5mb290IC53cmFwe2dyaWQtdGVtcGxhdGUtY29sdW1uczoyZnIgMWZyIDFmciAxZnJ9fQouZm9vdCBoNHtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxNHB4O21hcmdpbjowIDAgMTBweH0KLmZvb3QgcCwuZm9vdCBhe2ZvbnQtc2l6ZToxM3B4O2NvbG9yOiNCNkJCRDY7bGluZS1oZWlnaHQ6Mn0KLmZvb3QgLmNvbHMgYXtkaXNwbGF5OmJsb2NrfQouZm9vdC1ib3R0b217dGV4dC1hbGlnbjpjZW50ZXI7Zm9udC1zaXplOjEycHg7Y29sb3I6IzdCODFBMzttYXJnaW4tdG9wOjI2cHg7cGFkZGluZy10b3A6MTZweDtib3JkZXItdG9wOjFweCBzb2xpZCAjMjYyQzRBfQouc3RhdGljLXBhZ2V7cGFkZGluZzoyNnB4IDAgNTBweDttYXgtd2lkdGg6NzYwcHg7bWFyZ2luOjAgYXV0b30KLnN0YXRpYy1wYWdlIGgxe2ZvbnQtc2l6ZToyMnB4O21hcmdpbi1ib3R0b206MTRweH0KLnN0YXRpYy1wYWdlIC5ib2R5e3doaXRlLXNwYWNlOnByZS13cmFwO2xpbmUtaGVpZ2h0OjEuOTtjb2xvcjp2YXIoLS10eCl9CgovKiA9PT09PSDgpp/gp4vgprjgp43gpp8sIOCmsuCni+CmoeCmvuCmsCwg4Kas4Kaf4KauLeCmqOCnjeCmr+CmvuCmrSA9PT09PSAqLwoudG9hc3R7cG9zaXRpb246Zml4ZWQ7bGVmdDo1MCU7Ym90dG9tOjgwcHg7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTUwJSk7YmFja2dyb3VuZDojMTExO2NvbG9yOiNmZmY7cGFkZGluZzoxMHB4IDE4cHg7Ym9yZGVyLXJhZGl1czoxMHB4O29wYWNpdHk6MDtwb2ludGVyLWV2ZW50czpub25lO3RyYW5zaXRpb246b3BhY2l0eSAuMnM7ei1pbmRleDo5MDttYXgtd2lkdGg6ODh2dzt0ZXh0LWFsaWduOmNlbnRlcjtmb250LXNpemU6MTMuNXB4fQoudG9hc3Quc2hvd3tvcGFjaXR5OjF9Ci5zcGlue3dpZHRoOjM0cHg7aGVpZ2h0OjM0cHg7Ym9yZGVyOjNweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXRvcC1jb2xvcjp2YXIoLS1icmFuZCk7Ym9yZGVyLXJhZGl1czo1MCU7YW5pbWF0aW9uOnNwIC44cyBsaW5lYXIgaW5maW5pdGU7bWFyZ2luOjQwcHggYXV0b30KQGtleWZyYW1lcyBzcHt0b3t0cmFuc2Zvcm06cm90YXRlKDM2MGRlZyl9fQouc2tlbHtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zMikgMjUlLHZhcigtLWxuKSAzNyUsdmFyKC0tczIpIDYzJSk7YmFja2dyb3VuZC1zaXplOjQwMCUgMTAwJTthbmltYXRpb246c2sgMS40cyBlYXNlIGluZmluaXRlfQpAa2V5ZnJhbWVzIHNrezAle2JhY2tncm91bmQtcG9zaXRpb246MTAwJSAwfTEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjowIDB9fQouYm90dG9tbmF2e3Bvc2l0aW9uOmZpeGVkO2xlZnQ6MDtyaWdodDowO2JvdHRvbTowO3otaW5kZXg6MzU7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1sbik7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpO3BhZGRpbmctYm90dG9tOmVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKX0KLmJvdHRvbW5hdiBhe2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoycHg7cGFkZGluZzo4cHggMDtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdSk7cG9zaXRpb246cmVsYXRpdmV9Ci5ib3R0b21uYXYgYS5vbntjb2xvcjp2YXIoLS1icmFuZC1kKTtmb250LXdlaWdodDo3MDB9Ci5ib3R0b21uYXYgc3Zne3dpZHRoOjIxcHg7aGVpZ2h0OjIxcHg7ZmlsbDpub25lO3N0cm9rZTpjdXJyZW50Q29sb3I7c3Ryb2tlLXdpZHRoOjEuOH0KQG1lZGlhKG1pbi13aWR0aDo5MDBweCl7LmJvdHRvbW5hdntkaXNwbGF5Om5vbmV9fQpib2R5e3BhZGRpbmctYm90dG9tOjY0cHh9CkBtZWRpYShtaW4td2lkdGg6OTAwcHgpe2JvZHl7cGFkZGluZy1ib3R0b206MH19CkBtZWRpYShwcmVmZXJzLXJlZHVjZWQtbW90aW9uOnJlZHVjZSl7KnthbmltYXRpb246bm9uZSFpbXBvcnRhbnQ7dHJhbnNpdGlvbjpub25lIWltcG9ydGFudH19Cg==")
STORE_JS = _b64("J3VzZSBzdHJpY3QnOwovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4Kab4KeL4KafIOCmuOCmueCmvuCmr+CmvOCmlQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KY29uc3QgJD0ocyxyKT0+KHJ8fGRvY3VtZW50KS5xdWVyeVNlbGVjdG9yKHMpOwpjb25zdCBlbD0odGFnLGF0dHJzLC4uLmtpZHMpPT57Y29uc3Qgbj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KHRhZyk7Zm9yKGNvbnN0IGsgaW4gYXR0cnN8fHt9KXtpZihrPT09J2h0bWwnKW4uaW5uZXJIVE1MPWF0dHJzW2tdO2Vsc2UgaWYoay5zdGFydHNXaXRoKCdvbicpKW4uYWRkRXZlbnRMaXN0ZW5lcihrLnNsaWNlKDIpLGF0dHJzW2tdKTtlbHNlIGlmKGF0dHJzW2tdIT1udWxsKW4uc2V0QXR0cmlidXRlKGssYXR0cnNba10pO31mb3IoY29uc3QgayBvZiBraWRzLmZsYXQoKSlpZihrIT1udWxsKW4uYXBwZW5kQ2hpbGQodHlwZW9mIGs9PT0nc3RyaW5nJz9kb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShrKTprKTtyZXR1cm4gbjt9Owpjb25zdCBlc2M9cz0+U3RyaW5nKHM9PW51bGw/Jyc6cykucmVwbGFjZSgvWyY8PiInXS9nLGM9Pih7JyYnOicmYW1wOycsJzwnOicmbHQ7JywnPic6JyZndDsnLCciJzonJnF1b3Q7JywiJyI6JyYjMzk7J31bY10pKTsKY29uc3QgbW9uZXk9bj0+J+CnsycrTnVtYmVyKG58fDApLnRvTG9jYWxlU3RyaW5nKCdibi1CRCcpOwpjb25zdCBkZWJvdW5jZT0oZm4sbXMpPT57bGV0IHQ7cmV0dXJuKC4uLmEpPT57Y2xlYXJUaW1lb3V0KHQpO3Q9c2V0VGltZW91dCgoKT0+Zm4oLi4uYSksbXMpO307fTsKZnVuY3Rpb24gdG9hc3QobXNnKXtjb25zdCB0PSQoJyN0b2FzdCcpfHxkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGVsKCdkaXYnLHtpZDondG9hc3QnLGNsYXNzOid0b2FzdCd9KSk7dC50ZXh0Q29udGVudD1tc2c7dC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7Y2xlYXJUaW1lb3V0KHRvYXN0Ll90KTt0b2FzdC5fdD1zZXRUaW1lb3V0KCgpPT50LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKSwyNjAwKTt9CmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLG9wdCl7CiBjb25zdCByPWF3YWl0IGZldGNoKHBhdGgsT2JqZWN0LmFzc2lnbih7aGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfX0sb3B0KSk7CiBsZXQgaj1udWxsO3RyeXtqPWF3YWl0IHIuanNvbigpO31jYXRjaChfKXt9CiBpZighci5vayl0aHJvdyBuZXcgRXJyb3IoKGomJmouZXJyb3IpfHwn4KaP4KaV4Kaf4Ka/IOCmuOCmruCmuOCnjeCmr+CmviDgprngpq/gprzgp4fgppvgp4cnKTsKIHJldHVybiBqOwp9CmNvbnN0IElDT05TPXtjYXJ0Oic8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCI+PGNpcmNsZSBjeD0iOSIgY3k9IjIxIiByPSIxLjUiLz48Y2lyY2xlIGN4PSIxOSIgY3k9IjIxIiByPSIxLjUiLz48cGF0aCBkPSJNMiAzaDNsMi42IDEyLjZhMiAyIDAgMCAwIDIgMS42aDguOGEyIDIgMCAwIDAgMi0xLjZMMjIgN0g2Ii8+PC9zdmc+JywKIHNlYXJjaDonPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiPjxjaXJjbGUgY3g9IjExIiBjeT0iMTEiIHI9IjciLz48cGF0aCBkPSJtMjEgMjEtNC4zNS00LjM1Ii8+PC9zdmc+JywKIHVzZXI6Jzxzdmcgdmlld0JveD0iMCAwIDI0IDI0Ij48Y2lyY2xlIGN4PSIxMiIgY3k9IjgiIHI9IjQiLz48cGF0aCBkPSJNNCAyMWMxLjYtNCA1LTYgOC02czYuNCAyIDggNiIvPjwvc3ZnPicsCiBob21lOic8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTMgMTFsOS04IDkgOCIvPjxwYXRoIGQ9Ik01IDEwdjEwaDE0VjEwIi8+PC9zdmc+JywKIGdyaWQ6Jzxzdmcgdmlld0JveD0iMCAwIDI0IDI0Ij48cmVjdCB4PSIzIiB5PSIzIiB3aWR0aD0iNyIgaGVpZ2h0PSI3Ii8+PHJlY3QgeD0iMTQiIHk9IjMiIHdpZHRoPSI3IiBoZWlnaHQ9IjciLz48cmVjdCB4PSIzIiB5PSIxNCIgd2lkdGg9IjciIGhlaWdodD0iNyIvPjxyZWN0IHg9IjE0IiB5PSIxNCIgd2lkdGg9IjciIGhlaWdodD0iNyIvPjwvc3ZnPicsCiB3aGF0c2FwcDonPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9ImN1cnJlbnRDb2xvciIgc3Ryb2tlPSJub25lIj48cGF0aCBkPSJNMTIgMmExMCAxMCAwIDAgMC04LjYgMTVMMiAyMmw1LjItMS40QTEwIDEwIDAgMSAwIDEyIDJ6bTAgMTguMmE4LjIgOC4yIDAgMCAxLTQuMi0xLjJsLS4zLS4yLTMuMS44LjgtMy0uMi0uM0E4LjIgOC4yIDAgMSAxIDEyIDIwLjJ6bTQuNS02LjFjLS4yLS4xLTEuNS0uNy0xLjctLjgtLjItLjEtLjQtLjEtLjYuMS0uMi4yLS43LjgtLjggMS0uMi4yLS4zLjItLjUuMS0uMi0uMS0xLS40LTEuOS0xLjItLjctLjYtMS4yLTEuNC0xLjMtMS42LS4xLS4yIDAtLjQuMS0uNS4xLS4xLjItLjMuNC0uNC4xLS4xLjItLjIuMi0uNC4xLS4yIDAtLjMgMC0uNCAwLS4xLS42LTEuNS0uOC0yLS4yLS41LS40LS40LS42LS40aC0uNWMtLjIgMC0uNC4xLS42LjMtLjIuMi0uOC44LS44IDJzLjggMi4zIDEgMi41Yy4xLjIgMS42IDIuNSA0IDMuNS42LjIgMSAuNCAxLjMuNS42LjIgMS4xLjIgMS41LjEuNS0uMSAxLjUtLjYgMS43LTEuMi4yLS42LjItMS4xLjEtMS4yLS4xLS4xLS4yLS4yLS40LS4zeiIvPjwvc3ZnPid9OwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmheCmrOCmuOCnjeCmpeCmvjog4KaV4Ka+4Kaw4KeN4KafIChsb2NhbFN0b3JhZ2UpLCDgprjgpr7gpofgpp8g4Ka44KeH4Kaf4Ka/4KaC4Ka4CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpjb25zdCBDYXJ0PXsKIGl0ZW1zOltdLAogbG9hZCgpe3RyeXt0aGlzLml0ZW1zPUpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ2Rva2FuX2NhcnQnKXx8J1tdJyk7fWNhdGNoKF8pe3RoaXMuaXRlbXM9W107fWlmKCFBcnJheS5pc0FycmF5KHRoaXMuaXRlbXMpKXRoaXMuaXRlbXM9W107fSwKIHNhdmUoKXt0cnl7bG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2Rva2FuX2NhcnQnLEpTT04uc3RyaW5naWZ5KHRoaXMuaXRlbXMpKTt9Y2F0Y2goXyl7fSB0aGlzLnVwZGF0ZUJhZGdlKCk7fSwKIGFkZChwaWQsdmlkLHF0eSl7Y29uc3QgbD10aGlzLml0ZW1zLmZpbmQoeD0+eC5waWQ9PT1waWQmJngudmlkPT09dmlkKTtpZihsKWwucXR5PU1hdGgubWluKDIwLGwucXR5K3F0eSk7ZWxzZSB0aGlzLml0ZW1zLnB1c2goe3BpZCx2aWQ6dmlkfHwnJyxxdHk6TWF0aC5taW4oMjAscXR5KX0pO3RoaXMuc2F2ZSgpO30sCiBzZXRRdHkocGlkLHZpZCxxdHkpe2NvbnN0IGw9dGhpcy5pdGVtcy5maW5kKHg9PngucGlkPT09cGlkJiZ4LnZpZD09PXZpZCk7aWYobCl7aWYocXR5PD0wKXRoaXMucmVtb3ZlKHBpZCx2aWQpO2Vsc2V7bC5xdHk9TWF0aC5taW4oMjAscXR5KTt0aGlzLnNhdmUoKTt9fX0sCiByZW1vdmUocGlkLHZpZCl7dGhpcy5pdGVtcz10aGlzLml0ZW1zLmZpbHRlcih4PT4hKHgucGlkPT09cGlkJiZ4LnZpZD09PXZpZCkpO3RoaXMuc2F2ZSgpO30sCiBjbGVhcigpe3RoaXMuaXRlbXM9W107dGhpcy5zYXZlKCk7fSwKIGNvdW50KCl7cmV0dXJuIHRoaXMuaXRlbXMucmVkdWNlKChzLHgpPT5zK3gucXR5LDApO30sCiB1cGRhdGVCYWRnZSgpe2NvbnN0IG49dGhpcy5jb3VudCgpO2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5jYXJ0LWJhZGdlJykuZm9yRWFjaChiPT57Yi50ZXh0Q29udGVudD1uPjk5Pyc5OSsnOm47Yi5zdHlsZS5kaXNwbGF5PW4/J2ZsZXgnOidub25lJzt9KTt9Cn07CkNhcnQubG9hZCgpOwoKbGV0IENGRz1udWxsLCBDT1VQT049bnVsbDsKYXN5bmMgZnVuY3Rpb24gZW5zdXJlQ2ZnKCl7aWYoIUNGRylDRkc9YXdhaXQgYXBpKCcvYXBpL2NvbmZpZycpO3JldHVybiBDRkc7fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmsOCmvuCmieCmn+CmvuCmsCAo4Ka54KeN4Kav4Ka+4Ka2IOCmm+CmvuCmoeCmvOCmvuCmhyDgprjgp4Hgpqjgp43gpqbgprAgVVJMLCBIaXN0b3J5IEFQSSkKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmNvbnN0IFJvdXRlcj17cm91dGVzOltdLAogYWRkKHJ4LGZuKXt0aGlzLnJvdXRlcy5wdXNoKFtyeCxmbl0pO30sCiBnbyhwYXRoLHJlcGxhY2Upe2lmKHJlcGxhY2UpaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwnJyxwYXRoKTtlbHNlIGhpc3RvcnkucHVzaFN0YXRlKG51bGwsJycscGF0aCk7dGhpcy5yZW5kZXIoKTt9LAogYXN5bmMgcmVuZGVyKCl7CiAgY29uc3QgcGF0aD1sb2NhdGlvbi5wYXRobmFtZSwgcT1PYmplY3QuZnJvbUVudHJpZXMobmV3IFVSTFNlYXJjaFBhcmFtcyhsb2NhdGlvbi5zZWFyY2gpKTsKICB3aW5kb3cuc2Nyb2xsVG8oMCwwKTsKICBmb3IoY29uc3RbcngsZm5dIG9mIHRoaXMucm91dGVzKXtjb25zdCBtPXJ4LmV4ZWMocGF0aCk7aWYobSl7cm9vdC5pbm5lckhUTUw9JzxkaXYgY2xhc3M9InNwaW4iPjwvZGl2Pic7dHJ5e2F3YWl0IGZuKG0scSk7fWNhdGNoKGUpe3Jvb3QuaW5uZXJIVE1MPWVyckJveChlLm1lc3NhZ2UpO31yZXR1cm47fX0KICByb290LmlubmVySFRNTD1lcnJCb3goJ+CmquCmvuCmpOCmvuCmn+CmvyDgpqrgpr7gppPgpq/gprzgpr4g4Kav4Ka+4Kav4Ka84Kao4Ka/Jyk7CiB9fTsKZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGU9PnsKIGNvbnN0IGE9ZS50YXJnZXQuY2xvc2VzdCYmZS50YXJnZXQuY2xvc2VzdCgnYVtocmVmXj0iLyJdJyk7CiBpZighYXx8YS50YXJnZXQ9PT0nX2JsYW5rJ3x8ZS5tZXRhS2V5fHxlLmN0cmxLZXl8fGUuc2hpZnRLZXkpcmV0dXJuOwogZS5wcmV2ZW50RGVmYXVsdCgpO1JvdXRlci5nbyhhLmdldEF0dHJpYnV0ZSgnaHJlZicpKTsKfSk7CmFkZEV2ZW50TGlzdGVuZXIoJ3BvcHN0YXRlJywoKT0+Um91dGVyLnJlbmRlcigpKTsKZnVuY3Rpb24gZXJyQm94KG0pe3JldHVybiBgPGRpdiBjbGFzcz0iZW1wdHkiPjxwPvCfmJUgJHtlc2MobSl9PC9wPjxhIGNsYXNzPSJidG4iIGhyZWY9Ii8iPuCmueCni+CmruCnhyDgpqvgpr/gprDgp4Hgpqg8L2E+PC9kaXY+YDt9Cgpjb25zdCByb290PWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyb290Jyk7CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4Kay4KeH4KaG4KaJ4KafOiDgprngp4fgpqHgpr7gprAsIOCmq+CngeCmn+CmvuCmsCwg4KaV4Ka+4Kaw4KeN4KafIOCmoeCnjeCmsOCmr+CmvOCmvuCmsAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gbGF5b3V0KGlubmVyKXsKIHJldHVybiBgCiAke0NGRy5zaG9wLm5vdGljZT9gPGRpdiBjbGFzcz0idG9wYmFyIj4ke2VzYyhDRkcuc2hvcC5ub3RpY2UpfTwvZGl2PmA6Jyd9CiA8aGVhZGVyIGNsYXNzPSJoZHIiPjxkaXYgY2xhc3M9IndyYXAgaGRyLWluIj4KICA8YSBjbGFzcz0ibG9nbyIgaHJlZj0iLyI+JHtlc2MoQ0ZHLnNob3Auc2hvcF9uYW1lKX08L2E+CiAgPGZvcm0gY2xhc3M9InNlYXJjaGJhciIgaWQ9InNlYXJjaEZvcm0iIGF1dG9jb21wbGV0ZT0ib2ZmIj48aW5wdXQgaWQ9InNlYXJjaElucHV0IiBwbGFjZWhvbGRlcj0i4Kaq4Kaj4KeN4KavIOCmluCngeCmgeCmnOCngeCmqOKApiIgdmFsdWU9IiR7ZXNjKG5ldyBVUkxTZWFyY2hQYXJhbXMobG9jYXRpb24uc2VhcmNoKS5nZXQoJ3EnKXx8JycpfSI+PGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGFyaWEtbGFiZWw9IuCmluCngeCmgeCmnOCngeCmqCI+JHtJQ09OUy5zZWFyY2h9PC9idXR0b24+CiAgIDxkaXYgY2xhc3M9InN1Z2dlc3QiIGlkPSJzdWdnZXN0Qm94IiBoaWRkZW4+PC9kaXY+PC9mb3JtPgogIDxkaXYgY2xhc3M9ImhpY29ucyI+CiAgIDxhIGNsYXNzPSJoaWNvbiIgaHJlZj0iL3RyYWNrIiBhcmlhLWxhYmVsPSLgpoXgprDgp43gpqHgpr7gprAg4Kaf4KeN4Kaw4KeN4Kav4Ka+4KaVIj4ke0lDT05TLnVzZXJ9PC9hPgogICA8YnV0dG9uIGNsYXNzPSJoaWNvbiIgaWQ9ImNhcnRCdG4iIGFyaWEtbGFiZWw9IuCmleCmvuCmsOCnjeCmnyI+JHtJQ09OUy5jYXJ0fTxzcGFuIGNsYXNzPSJiYWRnZSBjYXJ0LWJhZGdlIiBzdHlsZT0iZGlzcGxheTpub25lIj48L3NwYW4+PC9idXR0b24+CiAgPC9kaXY+CiA8L2Rpdj4KIDxuYXYgY2xhc3M9ImNhdGJhciI+PGRpdiBjbGFzcz0id3JhcCI+CiAgPGEgaHJlZj0iL3Nob3AiIGNsYXNzPSIke2xvY2F0aW9uLnBhdGhuYW1lPT09Jy9zaG9wJyYmIWxvY2F0aW9uLnNlYXJjaC5pbmNsdWRlcygnYz0nKT8nb24nOicnfSI+4Ka44KasIOCmquCmo+CnjeCmrzwvYT4KICAke0NGRy5jYXRlZ29yaWVzLm1hcChjPT5gPGEgaHJlZj0iL3Nob3A/Yz0ke2MuaWR9IiBjbGFzcz0iJHtuZXcgVVJMU2VhcmNoUGFyYW1zKGxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdjJyk9PVN0cmluZyhjLmlkKT8nb24nOicnfSI+JHtlc2MoYy5pY29uKX0gJHtlc2MoYy5uYW1lKX08L2E+YCkuam9pbignJyl9CiA8L2Rpdj48L25hdj48L2hlYWRlcj4KIDxtYWluPiR7aW5uZXJ9PC9tYWluPgogJHtDRkcuc2hvcC53aGF0c2FwcD9gPGEgY2xhc3M9IndhLWZsb2F0IiBocmVmPSJodHRwczovL3dhLm1lLzg4JHtlc2MoQ0ZHLnNob3Aud2hhdHNhcHApfSIgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiIGFyaWEtbGFiZWw9IuCmueCni+Cmr+CmvOCmvuCmn+CmuOCmheCnjeCmr+CmvuCmquCnhyDgpq/gp4vgppfgpr7gpq/gp4vgppcg4KaV4Kaw4KeB4KaoIj4ke0lDT05TLndoYXRzYXBwfTwvYT5gOicnfQogPGZvb3RlciBjbGFzcz0iZm9vdCI+PGRpdiBjbGFzcz0id3JhcCI+CiAgPGRpdj48aDQ+JHtlc2MoQ0ZHLnNob3Auc2hvcF9uYW1lKX08L2g0PjxwPiR7ZXNjKENGRy5zaG9wLnRhZ2xpbmUpfTwvcD4KICAgJHtDRkcuc2hvcC5waG9uZT9gPHA+8J+TniA8YSBocmVmPSJ0ZWw6JHtlc2MoQ0ZHLnNob3AucGhvbmUpfSI+JHtlc2MoQ0ZHLnNob3AucGhvbmUpfTwvYT48L3A+YDonJ30ke0NGRy5zaG9wLndoYXRzYXBwP2A8cD7wn5KsIDxhIGhyZWY9Imh0dHBzOi8vd2EubWUvODgke2VzYyhDRkcuc2hvcC53aGF0c2FwcCl9IiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciI+4Ka54KeL4Kav4Ka84Ka+4Kaf4Ka44KaF4KeN4Kav4Ka+4KaqOiAke2VzYyhDRkcuc2hvcC53aGF0c2FwcCl9PC9hPjwvcD5gOicnfSR7Q0ZHLnNob3AuZW1haWw/YDxwPuKcie+4jyAke2VzYyhDRkcuc2hvcC5lbWFpbCl9PC9wPmA6Jyd9JHtDRkcuc2hvcC5hZGRyZXNzP2A8cD7wn5ONICR7ZXNjKENGRy5zaG9wLmFkZHJlc3MpfTwvcD5gOicnfTwvZGl2PgogIDxkaXYgY2xhc3M9ImNvbHMiPjxoND7gppXgp4fgpqjgpr7gppXgpr7gpp/gpr48L2g0PjxhIGhyZWY9Ii9zaG9wIj7gprjgpqwg4Kaq4Kaj4KeN4KavPC9hPjxhIGhyZWY9Ii9zaG9wP2RlYWw9MSI+4KaF4Kar4Ka+4KawPC9hPjxhIGhyZWY9Ii90cmFjayI+4KaF4Kaw4KeN4Kah4Ka+4KawIOCmn+CnjeCmsOCnjeCmr+CmvuCmlTwvYT48L2Rpdj4KICA8ZGl2IGNsYXNzPSJjb2xzIj48aDQ+4Ka44Ka54Ka+4Kav4Ka84Kak4Ka+PC9oND48YSBocmVmPSIvcGFnZS9yZXR1cm5zIj7gpqvgp4fgprDgpqQg4Kao4KeA4Kak4Ka/PC9hPjxhIGhyZWY9Ii9wYWdlL3Rlcm1zIj7gprbgprDgp43gpqTgpr7gpqzgprLgpr88L2E+PGEgaHJlZj0iL3BhZ2UvcHJpdmFjeSI+4KaX4KeL4Kaq4Kao4KeA4Kav4Ka84Kak4Ka+PC9hPjwvZGl2PgogIDxkaXYgY2xhc3M9ImNvbHMiPjxoND7gpqrgp43gprDgpqTgpr/gprfgp43gpqDgpr7gpqg8L2g0PjxhIGhyZWY9Ii9wYWdlL2Fib3V0Ij7gpobgpq7gpr7gpqbgp4fgprAg4Ka44Kau4KeN4Kaq4Kaw4KeN4KaV4KeHPC9hPjwvZGl2PgogPC9kaXY+PGRpdiBjbGFzcz0iZm9vdC1ib3R0b20iPsKpICR7bmV3IERhdGUoKS5nZXRGdWxsWWVhcigpfSAke2VzYyhDRkcuc2hvcC5zaG9wX25hbWUpfeClpCDgprjgprDgp43gpqzgprjgp43gpqzgpqTgp43gpqwg4Ka44KaC4Kaw4KaV4KeN4Ka34Ka/4Kak4KWkPC9kaXY+PC9mb290ZXI+CiA8bmF2IGNsYXNzPSJib3R0b21uYXYiPgogIDxhIGhyZWY9Ii8iIGNsYXNzPSIke2xvY2F0aW9uLnBhdGhuYW1lPT09Jy8nPydvbic6Jyd9Ij4ke0lDT05TLmhvbWV94Ka54KeL4KauPC9hPgogIDxhIGhyZWY9Ii9zaG9wIiBjbGFzcz0iJHtsb2NhdGlvbi5wYXRobmFtZT09PScvc2hvcCc/J29uJzonJ30iPiR7SUNPTlMuZ3JpZH3gprbgpqo8L2E+CiAgPGEgaHJlZj0iL3RyYWNrIiBjbGFzcz0iJHtsb2NhdGlvbi5wYXRobmFtZT09PScvdHJhY2snPydvbic6Jyd9Ij4ke0lDT05TLnVzZXJ94Kaf4KeN4Kaw4KeN4Kav4Ka+4KaVPC9hPgogIDxidXR0b24gaWQ9ImNhcnRCdG4yIj4ke0lDT05TLmNhcnR9PHNwYW4gY2xhc3M9ImJhZGdlIGNhcnQtYmFkZ2UiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPjwvc3Bhbj7gppXgpr7gprDgp43gpp88L2J1dHRvbj4KIDwvbmF2PgogPGRpdiBjbGFzcz0ib3ZlcmxheSIgaWQ9Im92Ij48L2Rpdj48ZGl2IGNsYXNzPSJkcmF3ZXIiIGlkPSJjYXJ0RHJhd2VyIj48L2Rpdj5gOwp9CmZ1bmN0aW9uIGJpbmRMYXlvdXQoKXsKIENhcnQudXBkYXRlQmFkZ2UoKTsKICQoJyNjYXJ0QnRuJykub25jbGljaz0kKCcjY2FydEJ0bjInKS5vbmNsaWNrPW9wZW5DYXJ0OwogJCgnI292Jykub25jbGljaz1jbG9zZUNhcnQ7CiBjb25zdCBmb3JtPSQoJyNzZWFyY2hGb3JtJyk7CiBmb3JtLm9uc3VibWl0PWU9PntlLnByZXZlbnREZWZhdWx0KCk7Y29uc3Qgdj0kKCcjc2VhcmNoSW5wdXQnKS52YWx1ZS50cmltKCk7JCgnI3N1Z2dlc3RCb3gnKS5oaWRkZW49dHJ1ZTtSb3V0ZXIuZ28oJy9zaG9wP3E9JytlbmNvZGVVUklDb21wb25lbnQodikpO307CiBjb25zdCBzdWc9JCgnI3N1Z2dlc3RCb3gnKTsKICQoJyNzZWFyY2hJbnB1dCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JyxkZWJvdW5jZShhc3luYyBlPT57CiAgY29uc3Qgdj1lLnRhcmdldC52YWx1ZS50cmltKCk7CiAgaWYodi5sZW5ndGg8Mil7c3VnLmhpZGRlbj10cnVlO3JldHVybjt9CiAgdHJ5e2NvbnN0IHtpdGVtc309YXdhaXQgYXBpKCcvYXBpL3N1Z2dlc3Q/cT0nK2VuY29kZVVSSUNvbXBvbmVudCh2KSk7CiAgIGlmKCFpdGVtcy5sZW5ndGgpe3N1Zy5oaWRkZW49dHJ1ZTtyZXR1cm47fQogICBzdWcuaW5uZXJIVE1MPWl0ZW1zLm1hcChpPT5gPGJ1dHRvbiB0eXBlPSJidXR0b24iIGRhdGEtaWQ9IiR7aS5pZH0iPiR7ZXNjKGkudGl0bGUpfTwvYnV0dG9uPmApLmpvaW4oJycpOwogICBzdWcuaGlkZGVuPWZhbHNlOwogICBzdWcucXVlcnlTZWxlY3RvckFsbCgnYnV0dG9uJykuZm9yRWFjaChiPT5iLm9uY2xpY2s9KCk9PntzdWcuaGlkZGVuPXRydWU7Um91dGVyLmdvKCcvcC8nK2IuZGF0YXNldC5pZCk7fSk7CiAgfWNhdGNoKF8pe30KIH0sMjUwKSk7CiBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsZT0+e2lmKCFlLnRhcmdldC5jbG9zZXN0KCcuc2VhcmNoYmFyJykpc3VnLmhpZGRlbj10cnVlO30pOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4KaV4Ka+4Kaw4KeN4KafIOCmoeCnjeCmsOCmr+CmvOCmvuCmsAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KbGV0IGNhcnRMaW5lcz1bXTsKYXN5bmMgZnVuY3Rpb24gb3BlbkNhcnQoKXsKICQoJyNvdicpLmNsYXNzTGlzdC5hZGQoJ29uJyk7Y29uc3QgZD0kKCcjY2FydERyYXdlcicpO2QuY2xhc3NMaXN0LmFkZCgnb24nKTsKIGQuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJkci1oZCI+PGgzPvCfm5Ig4KaV4Ka+4Kaw4KeN4KafPC9oMz48YnV0dG9uIGNsYXNzPSJkci1jbG9zZSIgaWQ9ImRyQ2xvc2UiPuKclTwvYnV0dG9uPjwvZGl2PjxkaXYgY2xhc3M9ImRyLWJvZHkiIGlkPSJkckJvZHkiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PmA7CiAkKCcjZHJDbG9zZScpLm9uY2xpY2s9Y2xvc2VDYXJ0OwogYXdhaXQgcmVmcmVzaENhcnQoKTsKfQpmdW5jdGlvbiBjbG9zZUNhcnQoKXskKCcjb3YnKS5jbGFzc0xpc3QucmVtb3ZlKCdvbicpOyQoJyNjYXJ0RHJhd2VyJykuY2xhc3NMaXN0LnJlbW92ZSgnb24nKTt9CmFzeW5jIGZ1bmN0aW9uIHJlZnJlc2hDYXJ0KCl7CiBjb25zdCBib2R5PSQoJyNkckJvZHknKTsgaWYoIWJvZHkpcmV0dXJuOwogaWYoIUNhcnQuaXRlbXMubGVuZ3RoKXtib2R5LmlubmVySFRNTD0nPGRpdiBjbGFzcz0iY2FydGVtcHR5Ij7wn5uSPHA+4KaG4Kaq4Kao4Ka+4KawIOCmleCmvuCmsOCnjeCmnyDgppbgpr7gprLgpr88L3A+PC9kaXY+JztyZW5kZXJDYXJ0Rm9vdCgwLDApO3JldHVybjt9CiBsZXQgZGF0YTt0cnl7ZGF0YT1hd2FpdCBhcGkoJy9hcGkvY2FydCcse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7aXRlbXM6Q2FydC5pdGVtc30pfSk7fWNhdGNoKGUpe2JvZHkuaW5uZXJIVE1MPWVyckJveChlLm1lc3NhZ2UpO3JldHVybjt9CiBjYXJ0TGluZXM9ZGF0YS5saW5lczsKIC8vIOCmheCmuOCmruCnjeCmreCmrC/gprjgp43gpp/gppUt4Kab4Ka+4Kah4Ka84Ka+IOCmsuCmvuCmh+CmqCDgppXgpr7gprDgp43gpp8g4Kal4KeH4KaV4KeHIOCmuOCmsOCmv+Cmr+CmvOCnhyDgpqbgpr/gpocKIGxldCBjaGFuZ2VkPWZhbHNlOwogZGF0YS5saW5lcy5mb3JFYWNoKGw9PntpZighbC5vayYmbC5zdG9jazw9MCl7Q2FydC5yZW1vdmUobC5waWQsbC52aWQpO2NoYW5nZWQ9dHJ1ZTt9ZWxzZSBpZihsLnF0eSE9PShDYXJ0Lml0ZW1zLmZpbmQoeD0+eC5waWQ9PT1sLnBpZCYmeC52aWQ9PT1sLnZpZCl8fHt9KS5xdHkpe2NvbnN0IGl0PUNhcnQuaXRlbXMuZmluZCh4PT54LnBpZD09PWwucGlkJiZ4LnZpZD09PWwudmlkKTtpZihpdCl7aXQucXR5PWwucXR5O2NoYW5nZWQ9dHJ1ZTt9fX0pOwogaWYoY2hhbmdlZClDYXJ0LnNhdmUoKTsKIGJvZHkuaW5uZXJIVE1MPWRhdGEubGluZXMubWFwKGw9PmAKICA8ZGl2IGNsYXNzPSJjaXRlbSIgZGF0YS1waWQ9IiR7bC5waWR9IiBkYXRhLXZpZD0iJHtlc2MobC52aWQpfSI+CiAgICR7bC5pbWc/YDxpbWcgc3JjPSIvdXBsb2Fkcy8ke2VzYyhsLmltZyl9IiBhbHQ9IiI+YDpgPGRpdiBjbGFzcz0iaWMyIj4ke2wuaWNvbnx8J/Cfm43vuI8nfTwvZGl2PmB9CiAgIDxkaXYgY2xhc3M9ImNpLWIiPjxkaXYgY2xhc3M9ImNpLXQiPjxhIGhyZWY9Ii9wLyR7bC5waWR9Ij4ke2VzYyhsLnRpdGxlKX08L2E+PC9kaXY+CiAgICAke2wudmlkP2A8ZGl2IGNsYXNzPSJjaS12Ij4ke2VzYyhsLnZpZCl9PC9kaXY+YDonJ30KICAgICR7IWwub2s/YDxkaXYgY2xhc3M9ImNpLXdhcm4iPiR7ZXNjKGwubXNnKX08L2Rpdj5gOicnfQogICAgPGRpdiBjbGFzcz0iY2ktcXR5Ij48YnV0dG9uIGNsYXNzPSJxbSI+4oiSPC9idXR0b24+PHNwYW4+JHtsLnF0eX08L3NwYW4+PGJ1dHRvbiBjbGFzcz0icXAiPis8L2J1dHRvbj48YSBjbGFzcz0iY2ktcm0iPuCmuOCmsOCmvuCmqDwvYT48L2Rpdj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iY2ktcHJpY2UiPiR7bW9uZXkobC5wcmljZSpsLnF0eSl9PC9kaXY+CiAgPC9kaXY+YCkuam9pbignJyk7CiBib2R5LnF1ZXJ5U2VsZWN0b3JBbGwoJy5jaXRlbScpLmZvckVhY2gocm93PT57CiAgY29uc3QgcGlkPStyb3cuZGF0YXNldC5waWQsIHZpZD1yb3cuZGF0YXNldC52aWQ7CiAgcm93LnF1ZXJ5U2VsZWN0b3IoJy5xbScpLm9uY2xpY2s9KCk9Pntjb25zdCBsPWNhcnRMaW5lcy5maW5kKHg9PngucGlkPT09cGlkJiZ4LnZpZD09PXZpZCk7Q2FydC5zZXRRdHkocGlkLHZpZCxsLnF0eS0xKTtyZWZyZXNoQ2FydCgpO307CiAgcm93LnF1ZXJ5U2VsZWN0b3IoJy5xcCcpLm9uY2xpY2s9KCk9Pntjb25zdCBsPWNhcnRMaW5lcy5maW5kKHg9PngucGlkPT09cGlkJiZ4LnZpZD09PXZpZCk7aWYobC5xdHk8bC5zdG9jaylDYXJ0LnNldFF0eShwaWQsdmlkLGwucXR5KzEpO2Vsc2UgdG9hc3QoJ+CmuOCnjeCmn+CmleCnhyDgpobgprAg4Kao4KeH4KaHJyk7fTsKICByb3cucXVlcnlTZWxlY3RvcignLmNpLXJtJykub25jbGljaz0oKT0+e0NhcnQucmVtb3ZlKHBpZCx2aWQpO3JlZnJlc2hDYXJ0KCk7fTsKIH0pOwogY29uc3Qgc3ViPWRhdGEubGluZXMuZmlsdGVyKGw9Pmwub2spLnJlZHVjZSgocyxsKT0+cytsLnByaWNlKmwucXR5LDApOwogcmVuZGVyQ2FydEZvb3Qoc3ViLGRhdGEubGluZXMuZmlsdGVyKGw9Pmwub2spLmxlbmd0aCk7Cn0KZnVuY3Rpb24gcmVuZGVyQ2FydEZvb3Qoc3ViLG9rQ291bnQpewogY29uc3QgZD0kKCcjY2FydERyYXdlcicpOyBpZighZClyZXR1cm47CiBsZXQgZm9vdD1kLnF1ZXJ5U2VsZWN0b3IoJy5kci1mb290Jyk7CiBpZighZm9vdCl7Zm9vdD1lbCgnZGl2Jyx7Y2xhc3M6J2RyLWZvb3QnfSk7ZC5hcHBlbmRDaGlsZChmb290KTt9CiBpZighb2tDb3VudCl7Zm9vdC5pbm5lckhUTUw9Jyc7cmV0dXJuO30KIGZvb3QuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJzdW1yb3cgdG90Ij48c3Bhbj7gprjgpr7gpqzgpp/gp4vgpp/gpr7gprI8L3NwYW4+PGI+JHttb25leShzdWIpfTwvYj48L2Rpdj4KICA8cCBzdHlsZT0iZm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tbXUpO21hcmdpbjo0cHggMCAxMHB4Ij7gpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Kaa4Ka+4Kaw4KeN4KacIOCmkyDgppvgpr7gpqHgprwg4Kaa4KeH4KaV4KaG4KaJ4Kaf4KeHIOCmpuCnh+CmluCmvuCmqOCniyDgprngpqzgp4c8L3A+CiAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJsb2NrIiBpZD0idG9DaGVja291dCI+4Kaa4KeH4KaV4KaG4KaJ4KafIOCmleCmsOCngeCmqDwvYnV0dG9uPmA7CiAkKCcjdG9DaGVja291dCcpLm9uY2xpY2s9KCk9PntjbG9zZUNhcnQoKTtSb3V0ZXIuZ28oJy9jaGVja291dCcpO307Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgprngp4vgpq4g4Kaq4Ka+4Kak4Ka+CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpSb3V0ZXIuYWRkKC9eXC8kLywgYXN5bmMoKT0+ewogYXdhaXQgZW5zdXJlQ2ZnKCk7CiBjb25zdCBkYXRhPWF3YWl0IGFwaSgnL2FwaS9ob21lJyk7CiByb290LmlubmVySFRNTD1sYXlvdXQoYAogIDxkaXYgY2xhc3M9IndyYXAgaGVybyI+JHtiYW5uZXJIdG1sKGRhdGEuYmFubmVycyl9PC9kaXY+CiAgJHtDRkcuc2hvcC5ub3RpY2U/Jyc6Jyd9CiAgPGRpdiBjbGFzcz0id3JhcCBzZWMiPjxkaXYgY2xhc3M9InNlYy1oIj48aDI+8J+Xgu+4jyDgppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr88L2gyPjwvZGl2PgogICA8ZGl2IGNsYXNzPSJjYXRncmlkIj4ke2RhdGEuY2F0ZWdvcmllcy5tYXAoYz0+YDxhIGNsYXNzPSJjYXRjYXJkIiBocmVmPSIvc2hvcD9jPSR7Yy5pZH0iPjxzcGFuIGNsYXNzPSJpYyI+JHtlc2MoYy5pY29uKX08L3NwYW4+PHNwYW4+JHtlc2MoYy5uYW1lKX08L3NwYW4+PC9hPmApLmpvaW4oJycpfHwnPHAgY2xhc3M9ImVtcHR5Ij7gppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr8g4KaP4KaW4Kao4KeLIOCmr+Cni+CmlyDgppXgprDgpr4g4Ka54Kav4Ka84Kao4Ka/PC9wPid9PC9kaXY+PC9kaXY+CiAgJHtkYXRhLmRlYWxzLmxlbmd0aD9zZWN0aW9uKCfwn5SlIOCmmuCmsuCmm+CnhyDgpoXgpqvgpr7gprAnLCcvc2hvcD9kZWFsPTEnLGRhdGEuZGVhbHMsdHJ1ZSk6Jyd9CiAgJHtkYXRhLmZlYXR1cmVkLmxlbmd0aD9zZWN0aW9uKCfinKgg4Kar4Ka/4Kaa4Ka+4Kaw4KeN4KahIOCmquCmo+CnjeCmrycsJy9zaG9wJyxkYXRhLmZlYXR1cmVkLHRydWUpOicnfQogICR7ZGF0YS5wb3B1bGFyLmxlbmd0aD9zZWN0aW9uKCfwn4+GIOCmnOCmqOCmquCnjeCmsOCmv+Cmr+CmvCDgpqrgpqPgp43gpq8nLCcvc2hvcD9zb3J0PXBvcHVsYXInLGRhdGEucG9wdWxhcix0cnVlKTonJ30KIGApOwogYmluZExheW91dCgpO2Jhbm5lclNsaWRlcigpOwp9KTsKZnVuY3Rpb24gYmFubmVySHRtbChiYW5uZXJzKXsKIGlmKCFiYW5uZXJzLmxlbmd0aClyZXR1cm4gYDxkaXYgY2xhc3M9ImhzbGlkZSIgc3R5bGU9ImJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEyMGRlZywke0NGRy5zaG9wLmJyYW5kfSwjMzMzKSI+PGRpdiBjbGFzcz0iaW4iPjxoMj4ke2VzYyhDRkcuc2hvcC5zaG9wX25hbWUpfTwvaDI+PHA+JHtlc2MoQ0ZHLnNob3AudGFnbGluZSl9PC9wPjwvZGl2PjwvZGl2PmA7CiByZXR1cm4gYDxkaXYgaWQ9ImJzbGlkZXIiPiR7YmFubmVycy5tYXAoKGIsaSk9PmA8ZGl2IGNsYXNzPSJoc2xpZGUiIHN0eWxlPSJiYWNrZ3JvdW5kOiR7ZXNjKGIuY29sb3IpfTtkaXNwbGF5OiR7aT8nbm9uZSc6J2ZsZXgnfSIgZGF0YS1pPSIke2l9Ij4KICAke2IuaW1hZ2U/YDxpbWcgc3JjPSIvdXBsb2Fkcy8ke2VzYyhiLmltYWdlKX0iIGFsdD0iIj5gOicnfTxkaXYgY2xhc3M9ImluIj48aDI+JHtlc2MoYi50aXRsZSl9PC9oMj4ke2Iuc3VidGl0bGU/YDxwPiR7ZXNjKGIuc3VidGl0bGUpfTwvcD5gOicnfTwvZGl2PjwvZGl2PmApLmpvaW4oJycpfQogICR7YmFubmVycy5sZW5ndGg+MT9gPGRpdiBjbGFzcz0iaGRvdHMiPiR7YmFubmVycy5tYXAoKF8saSk9PmA8aSBjbGFzcz0iJHtpPycnOidvbid9Ij48L2k+YCkuam9pbignJyl9PC9kaXY+YDonJ308L2Rpdj5gOwogfQpmdW5jdGlvbiBiYW5uZXJTbGlkZXIoKXsKIGNvbnN0IHdyYXA9JCgnI2JzbGlkZXInKTsgaWYoIXdyYXApcmV0dXJuOwogY29uc3Qgc2xpZGVzPVsuLi53cmFwLnF1ZXJ5U2VsZWN0b3JBbGwoJy5oc2xpZGUnKV0sIGRvdHM9Wy4uLndyYXAucXVlcnlTZWxlY3RvckFsbCgnLmhkb3RzIGknKV07CiBsZXQgaT0wOwogc2xpZGVzLmZvckVhY2gocz0+e2NvbnN0IGI9QkFOTkVSX0xJTktTW3MuZGF0YXNldC5pXTtpZihiKXMuc3R5bGUuY3Vyc29yPSdwb2ludGVyJzt9KTsKIGNsZWFySW50ZXJ2YWwoYmFubmVyU2xpZGVyLl90KTsKIGlmKHNsaWRlcy5sZW5ndGg8MilyZXR1cm47CiBiYW5uZXJTbGlkZXIuX3Q9c2V0SW50ZXJ2YWwoKCk9PntzbGlkZXNbaV0uc3R5bGUuZGlzcGxheT0nbm9uZSc7ZG90c1tpXSYmZG90c1tpXS5jbGFzc0xpc3QucmVtb3ZlKCdvbicpO2k9KGkrMSklc2xpZGVzLmxlbmd0aDtzbGlkZXNbaV0uc3R5bGUuZGlzcGxheT0nZmxleCc7ZG90c1tpXSYmZG90c1tpXS5jbGFzc0xpc3QuYWRkKCdvbicpO30sNDIwMCk7Cn0KbGV0IEJBTk5FUl9MSU5LUz17fTsKZnVuY3Rpb24gc2VjdGlvbih0aXRsZSxocmVmLGl0ZW1zLHNjcm9sbCl7CiByZXR1cm4gYDxkaXYgY2xhc3M9IndyYXAgc2VjIj48ZGl2IGNsYXNzPSJzZWMtaCI+PGgyPiR7dGl0bGV9PC9oMj48YSBocmVmPSIke2hyZWZ9Ij7gprjgpqwg4Kam4KeH4KaW4KeB4KaoIOKAujwvYT48L2Rpdj4KICA8ZGl2IGNsYXNzPSJwZ3JpZCR7c2Nyb2xsPycgcm93JzonJ30iPiR7aXRlbXMubWFwKHByb2R1Y3RDYXJkKS5qb2luKCcnKX08L2Rpdj48L2Rpdj5gOwp9CmZ1bmN0aW9uIHByb2R1Y3RDYXJkKHApewogY29uc3Qgb2ZmPXAub2ZmPjA/YDxzcGFuIGNsYXNzPSJwb2ZmIj4tJHtwLm9mZn0lPC9zcGFuPmA6Jyc7CiBjb25zdCBvdXQ9cC5zdG9jazw9MDsKIHJldHVybiBgPGEgY2xhc3M9InBjYXJkIiBocmVmPSIvcC8ke3AuaWR9Ij4KICA8ZGl2IGNsYXNzPSJwaW1nIj4ke29mZn0ke3AuaW1nP2A8aW1nIHNyYz0iL3VwbG9hZHMvJHtlc2MocC5pbWcpfSIgYWx0PSIke2VzYyhwLnRpdGxlKX0iIGxvYWRpbmc9ImxhenkiPmA6ZXNjKHAuaWNvbil9JHtvdXQ/JzxkaXYgY2xhc3M9InBzb2xkIj7gprjgp43gpp/gppUg4Ka24KeH4Ka3PC9kaXY+JzonJ308L2Rpdj4KICA8ZGl2IGNsYXNzPSJwYm9keSI+PGRpdiBjbGFzcz0icHRpdGxlIj4ke2VzYyhwLnRpdGxlKX08L2Rpdj4KICAgPGRpdiBjbGFzcz0icHByaWNlIj48Yj4ke21vbmV5KHAuZmluYWwpfTwvYj4ke3Auc2FsZT9gPHM+JHttb25leShwLnByaWNlKX08L3M+YDonJ308L2Rpdj4KICAgJHtwLnNvbGQ+MD9gPGRpdiBjbGFzcz0icHNvbGQtbGluZSI+JHtwLnNvbGR9KyDgpqzgpr/gppXgp43gprDgpr8g4Ka54Kav4Ka84KeH4Kab4KeHPC9kaXY+YDonJ308L2Rpdj48L2E+YDsKfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmtuCmqiAvIOCmuOCmvuCmsOCnjeCmmiDgpqrgpr7gpqTgpr4KICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovClJvdXRlci5hZGQoL15cL3Nob3AkLywgYXN5bmMobSxxKT0+ewogYXdhaXQgZW5zdXJlQ2ZnKCk7CiByb290LmlubmVySFRNTD1sYXlvdXQoYDxkaXYgY2xhc3M9IndyYXAgc2VjIj48ZGl2IGlkPSJzaG9wSGVhZCI+PC9kaXY+PGRpdiBpZD0ic2hvcEJvZHkiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PjwvZGl2PmApOwogYmluZExheW91dCgpOwogcmVuZGVyU2hvcEhlYWQocSk7CiBhd2FpdCBsb2FkU2hvcChxKTsKfSk7CmZ1bmN0aW9uIHJlbmRlclNob3BIZWFkKHEpewogY29uc3QgYWN0aXZlPWs9PnFba10/JyBjbGFzcz0iY2hpcCBvbiInOicgY2xhc3M9ImNoaXAiJzsKICQoJyNzaG9wSGVhZCcpLmlubmVySFRNTD1gCiAgPGRpdiBjbGFzcz0ic2hvcGhlYWQiPgogICA8YnV0dG9uIGRhdGEtZj0ic29ydCIgZGF0YS12PSIiIGNsYXNzPSJjaGlwJHshcS5zb3J0Pycgb24nOicnfSI+4Ka44Ka+4Kac4Ka+4Kao4KeLPC9idXR0b24+CiAgIDxidXR0b24gZGF0YS1mPSJzb3J0IiBkYXRhLXY9Im5ldyIke3Euc29ydD09PSduZXcnPycgY2xhc3M9ImNoaXAgb24iJzonIGNsYXNzPSJjaGlwIid9PuCmqOCmpOCngeCmqDwvYnV0dG9uPgogICA8YnV0dG9uIGRhdGEtZj0ic29ydCIgZGF0YS12PSJwcmljZV9hc2MiJHtxLnNvcnQ9PT0ncHJpY2VfYXNjJz8nIGNsYXNzPSJjaGlwIG9uIic6JyBjbGFzcz0iY2hpcCInfT7gppXgpq4g4Kam4Ka+4KauPC9idXR0b24+CiAgIDxidXR0b24gZGF0YS1mPSJzb3J0IiBkYXRhLXY9InByaWNlX2Rlc2MiJHtxLnNvcnQ9PT0ncHJpY2VfZGVzYyc/JyBjbGFzcz0iY2hpcCBvbiInOicgY2xhc3M9ImNoaXAiJ30+4Kas4KeH4Ka24Ka/IOCmpuCmvuCmrjwvYnV0dG9uPgogICA8YnV0dG9uIGRhdGEtZj0ic29ydCIgZGF0YS12PSJvZmYiJHtxLnNvcnQ9PT0nb2ZmJz8nIGNsYXNzPSJjaGlwIG9uIic6JyBjbGFzcz0iY2hpcCInfT7gpqzgp4fgprbgpr8g4Kab4Ka+4Kah4Ka8PC9idXR0b24+CiAgIDxidXR0b24gZGF0YS1mPSJkZWFsIiBkYXRhLXY9IjEiJHtxLmRlYWw9PT0nMSc/JyBjbGFzcz0iY2hpcCBvbiInOicgY2xhc3M9ImNoaXAiJ30+8J+UpSDgpoXgpqvgpr7gprA8L2J1dHRvbj4KICA8L2Rpdj4KICA8cCBzdHlsZT0iY29sb3I6dmFyKC0tbXUpO2ZvbnQtc2l6ZToxMy41cHg7bWFyZ2luOjRweCAwIDAiPiR7cS5xP2AiJHtlc2MocS5xKX0iIOCmj+CmsCDgppzgpqjgp43gpq8g4Kar4Kay4Ka+4Kar4KayYDon4Ka44KasIOCmquCmo+CnjeCmryd9PC9wPmA7CiAkKCcjc2hvcEhlYWQnKS5xdWVyeVNlbGVjdG9yQWxsKCdbZGF0YS1mXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT57CiAgY29uc3QgbnE9bmV3IFVSTFNlYXJjaFBhcmFtcyhsb2NhdGlvbi5zZWFyY2gpOwogIGNvbnN0IGN1cj1ucS5nZXQoYi5kYXRhc2V0LmYpOwogIGlmKGN1cj09PWIuZGF0YXNldC52fHwhYi5kYXRhc2V0LnYpbnEuZGVsZXRlKGIuZGF0YXNldC5mKTtlbHNlIG5xLnNldChiLmRhdGFzZXQuZixiLmRhdGFzZXQudik7CiAgbnEuZGVsZXRlKCdwYWdlJyk7CiAgUm91dGVyLmdvKCcvc2hvcD8nK25xLnRvU3RyaW5nKCkpOwogfSk7Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZFNob3AocSl7CiBjb25zdCBkYXRhPWF3YWl0IGFwaSgnL2FwaS9wcm9kdWN0cz8nK25ldyBVUkxTZWFyY2hQYXJhbXMocSkudG9TdHJpbmcoKSk7CiBjb25zdCBib2R5PSQoJyNzaG9wQm9keScpOwogaWYoIWRhdGEuaXRlbXMubGVuZ3RoKXtib2R5LmlubmVySFRNTD0nPGRpdiBjbGFzcz0iZW1wdHkiPvCfmJU8cD7gppXgp4vgpqjgp4sg4Kaq4Kaj4KeN4KavIOCmquCmvuCmk+Cmr+CmvOCmviDgpq/gpr7gpq/gprzgpqjgpr88L3A+PC9kaXY+JztyZXR1cm47fQogYm9keS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9InBncmlkIj4ke2RhdGEuaXRlbXMubWFwKHByb2R1Y3RDYXJkKS5qb2luKCcnKX08L2Rpdj4KICAke2RhdGEucGFnZXM+MT9gPGRpdiBjbGFzcz0icGFnZXIiPiR7cGFnZXJCdG5zKGRhdGEucGFnZSxkYXRhLnBhZ2VzKX08L2Rpdj5gOicnfWA7CiBib2R5LnF1ZXJ5U2VsZWN0b3JBbGwoJy5wYWdlciBidXR0b25bZGF0YS1wXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT57Y29uc3QgbnE9bmV3IFVSTFNlYXJjaFBhcmFtcyhsb2NhdGlvbi5zZWFyY2gpO25xLnNldCgncGFnZScsYi5kYXRhc2V0LnApO1JvdXRlci5nbygnL3Nob3A/JytucS50b1N0cmluZygpKTt9KTsKfQpmdW5jdGlvbiBwYWdlckJ0bnMocGFnZSxwYWdlcyl7CiBsZXQgb3V0PVtdOwogZm9yKGxldCBpPU1hdGgubWF4KDEscGFnZS0yKTtpPD1NYXRoLm1pbihwYWdlcyxwYWdlKzIpO2krKylvdXQucHVzaChgPGJ1dHRvbiBkYXRhLXA9IiR7aX0iIGNsYXNzPSIke2k9PT1wYWdlPydvbic6Jyd9Ij4ke2l9PC9idXR0b24+YCk7CiByZXR1cm4gb3V0LmpvaW4oJycpOwp9CndpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdwb3BzdGF0ZScsKCk9PntpZihsb2NhdGlvbi5wYXRobmFtZT09PScvc2hvcCcmJiQoJyNzaG9wSGVhZCcpKXtjb25zdCBxPU9iamVjdC5mcm9tRW50cmllcyhuZXcgVVJMU2VhcmNoUGFyYW1zKGxvY2F0aW9uLnNlYXJjaCkpO3JlbmRlclNob3BIZWFkKHEpO2xvYWRTaG9wKHEpO319KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpqrgpqPgp43gpq/gp4fgprAg4Kas4Ka/4Ka44KeN4Kak4Ka+4Kaw4Ka/4KakIOCmquCmvuCmpOCmvgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KUm91dGVyLmFkZCgvXlwvcFwvKFxkKykkLywgYXN5bmMgbT0+ewogYXdhaXQgZW5zdXJlQ2ZnKCk7CiBjb25zdCB7cHJvZHVjdDpwLHJlbGF0ZWR9PWF3YWl0IGFwaSgnL2FwaS9wcm9kdWN0LycrbVsxXSk7CiBsZXQgY3VySW1nPTAsIHNlbD1wLnZhcmlhbnRzLmxlbmd0aD9wLnZhcmlhbnRzWzBdOm51bGw7CiByb290LmlubmVySFRNTD1sYXlvdXQoYDxkaXYgY2xhc3M9IndyYXAiPjxkaXYgY2xhc3M9InBkdmlldyI+CiAgPGRpdj48ZGl2IGNsYXNzPSJnYWwtbWFpbiIgaWQ9ImdhbE1haW4iPiR7cC5pbWFnZXMubGVuZ3RoP2A8aW1nIHNyYz0iL3VwbG9hZHMvJHtlc2MocC5pbWFnZXNbMF0pfSIgYWx0PSIke2VzYyhwLnRpdGxlKX0iPmA6ZXNjKHAuaWNvbnx8J/Cfm43vuI8nKX08L2Rpdj4KICAgJHtwLmltYWdlcy5sZW5ndGg+MT9gPGRpdiBjbGFzcz0iZ2FsLXRodW1icyI+JHtwLmltYWdlcy5tYXAoKGltLGkpPT5gPGltZyBzcmM9Ii91cGxvYWRzLyR7ZXNjKGltKX0iIGRhdGEtaT0iJHtpfSIgY2xhc3M9IiR7aT8nJzonb24nfSI+YCkuam9pbignJyl9PC9kaXY+YDonJ308L2Rpdj4KICA8ZGl2PgogICA8aDEgY2xhc3M9InBkLXRpdGxlIj4ke2VzYyhwLnRpdGxlKX08L2gxPgogICA8ZGl2IGNsYXNzPSJwZC1tZXRhIj4ke3Auc29sZD4wP2Ake3Auc29sZH0rIOCmrOCmv+CmleCnjeCmsOCmvyDgprngpq/gprzgp4fgppvgp4dgOifgpqjgpqTgp4Hgpqgg4Kaq4Kaj4KeN4KavJ30ke3AuY2F0bmFtZT8nIMK3ICcrZXNjKHAuY2F0bmFtZSk6Jyd9PC9kaXY+CiAgIDxkaXYgY2xhc3M9InBkLXByaWNlIiBpZD0icHJpY2VCb3giPjwvZGl2PgogICAke3AudmFyaWFudHMubGVuZ3RoP2A8ZGl2PjxiIHN0eWxlPSJmb250LXNpemU6MTMuNXB4Ij7gpq3gp4fgprDgpr/gpq/gprzgp4fgpqjgp43gpp8g4Kas4KeH4Kab4KeHIOCmqOCmv+CmqDo8L2I+PGRpdiBjbGFzcz0idnJvdyIgaWQ9InZyb3ciPiR7cC52YXJpYW50cy5tYXAoKHYsaSk9PmA8YnV0dG9uIGNsYXNzPSJ2Y2hpcCR7aT8nJzonIG9uJ30iIGRhdGEtaT0iJHtpfSIgJHt2LnN0b2NrPD0wPydkaXNhYmxlZCc6Jyd9PiR7ZXNjKHYubGFiZWwpfTwvYnV0dG9uPmApLmpvaW4oJycpfTwvZGl2PjwvZGl2PmA6Jyd9CiAgIDxkaXYgY2xhc3M9InN0b2NrbGluZSIgaWQ9InN0b2NrTGluZSI+PC9kaXY+CiAgIDxkaXYgY2xhc3M9InF0eXJvdyI+PGJ1dHRvbiBpZD0icW0iPuKIkjwvYnV0dG9uPjxzcGFuIGlkPSJxdiI+MTwvc3Bhbj48YnV0dG9uIGlkPSJxcCI+KzwvYnV0dG9uPjwvZGl2PgogICA8ZGl2IGNsYXNzPSJwZC1hY3RzIj48YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QgYmlnIiBpZD0iYWRkQ2FydCI+8J+bkiDgppXgpr7gprDgp43gpp/gp4cg4Kav4KeL4KaXIOCmleCmsOCngeCmqDwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biBiaWciIGlkPSJidXlOb3ciPuCmj+CmluCmqOCmhyDgppXgpr/gpqjgp4Hgpqg8L2J1dHRvbj48L2Rpdj4KICAgPGRpdiBjbGFzcz0idHJ1c3Ryb3ciPjxzcGFuPvCfmpog4Kam4KeN4Kaw4KeB4KakIOCmoeCnh+CmsuCmv+CmreCmvuCmsOCmvzwvc3Bhbj48c3Bhbj7ihqnvuI8g4KetIOCmpuCmv+CmqOCnhyDgpqvgp4fgprDgpqQ8L3NwYW4+PHNwYW4+8J+StSDgppXgp43gpq/gpr7gprYg4KaF4KaoIOCmoeCnh+CmsuCmv+CmreCmvuCmsOCmvzwvc3Bhbj48L2Rpdj4KICAgPGRpdiBjbGFzcz0idGFiczIiPjxidXR0b24gY2xhc3M9Im9uIiBkYXRhLXQ9ImQiPuCmrOCmv+CmrOCmsOCmozwvYnV0dG9uPiR7cC5zcGVjcy5sZW5ndGg/JzxidXR0b24gZGF0YS10PSJzIj7gpqzgp4jgprbgpr/gprfgp43gpp/gp43gpq88L2J1dHRvbj4nOicnfTwvZGl2PgogICA8ZGl2IGlkPSJ0YWJCb2R5Ij48L2Rpdj4KICA8L2Rpdj48L2Rpdj4KICAke3JlbGF0ZWQubGVuZ3RoP3NlY3Rpb24oJ+Cmj+CmleCmhyDgpqfgprDgpqjgp4fgprAg4Kaq4Kaj4KeN4KavJywnL3Nob3AnLHJlbGF0ZWQsdHJ1ZSk6Jyd9CiA8L2Rpdj5gKTsKIGJpbmRMYXlvdXQoKTsKIGNvbnN0IGltZ3M9Wy4uLmRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5nYWwtdGh1bWJzIGltZycpXTsKIGltZ3MuZm9yRWFjaChpbT0+aW0ub25jbGljaz0oKT0+e2N1ckltZz0raW0uZGF0YXNldC5pOyQoJyNnYWxNYWluJykuaW5uZXJIVE1MPWA8aW1nIHNyYz0iL3VwbG9hZHMvJHtlc2MocC5pbWFnZXNbY3VySW1nXSl9IiBhbHQ9IiI+YDtpbWdzLmZvckVhY2goeD0+eC5jbGFzc0xpc3QucmVtb3ZlKCdvbicpKTtpbS5jbGFzc0xpc3QuYWRkKCdvbicpO30pOwogZnVuY3Rpb24gc3RvY2tOb3coKXtyZXR1cm4gc2VsP3NlbC5zdG9jazpwLnN0b2NrO30KIGZ1bmN0aW9uIHByaWNlTm93KCl7cmV0dXJuIHNlbD9zZWwucHJpY2U6cC5maW5hbDt9CiBmdW5jdGlvbiByZW5kZXJQcmljZSgpewogIGNvbnN0IGJhc2U9cC5wcmljZSwgZmluPXByaWNlTm93KCk7CiAgJCgnI3ByaWNlQm94JykuaW5uZXJIVE1MPWZpbjxiYXNlP2A8Yj4ke21vbmV5KGZpbil9PC9iPjxzPiR7bW9uZXkoYmFzZSl9PC9zPjxzcGFuIGNsYXNzPSJwZC1vZmYiPi0ke01hdGgucm91bmQoKGJhc2UtZmluKSoxMDAvYmFzZSl9JTwvc3Bhbj5gOmA8Yj4ke21vbmV5KGZpbil9PC9iPmA7CiAgY29uc3Qgc3Q9c3RvY2tOb3coKTsKICAkKCcjc3RvY2tMaW5lJykuY2xhc3NOYW1lPSdzdG9ja2xpbmUgJysoc3Q+MD8oc3Q8PTU/J2xvdyc6J29rJyk6JycpOwogICQoJyNzdG9ja0xpbmUnKS50ZXh0Q29udGVudD1zdD4wPyhzdDw9NT9g4Kau4Ka+4Kak4KeN4KawICR7c3R94Kaf4Ka/IOCmrOCmvuCmleCmvyDgpobgppvgp4dgOifgprjgp43gpp/gppXgp4cg4KaG4Kab4KeHJyk6J+CmuOCnjeCmn+CmlSDgprbgp4fgprcnOwogICQoJyNhZGRDYXJ0JykuZGlzYWJsZWQ9JCgnI2J1eU5vdycpLmRpc2FibGVkPXN0PD0wOwogIGNvbnN0IHF2PSQoJyNxdicpOyBpZigrcXYudGV4dENvbnRlbnQ+c3QpcXYudGV4dENvbnRlbnQ9TWF0aC5tYXgoMSxzdCk7CiB9CiByZW5kZXJQcmljZSgpOwogaWYocC52YXJpYW50cy5sZW5ndGgpZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnZjaGlwJykuZm9yRWFjaChiPT5iLm9uY2xpY2s9KCk9PntpZihiLmRpc2FibGVkKXJldHVybjtkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudmNoaXAnKS5mb3JFYWNoKHg9PnguY2xhc3NMaXN0LnJlbW92ZSgnb24nKSk7Yi5jbGFzc0xpc3QuYWRkKCdvbicpO3NlbD1wLnZhcmlhbnRzWytiLmRhdGFzZXQuaV07JCgnI3F2JykudGV4dENvbnRlbnQ9JzEnO3JlbmRlclByaWNlKCk7fSk7CiAkKCcjcW0nKS5vbmNsaWNrPSgpPT57Y29uc3Qgdj0kKCcjcXYnKTt2LnRleHRDb250ZW50PU1hdGgubWF4KDEsK3YudGV4dENvbnRlbnQtMSk7fTsKICQoJyNxcCcpLm9uY2xpY2s9KCk9Pntjb25zdCB2PSQoJyNxdicpO3YudGV4dENvbnRlbnQ9TWF0aC5taW4oc3RvY2tOb3coKSwyMCwrdi50ZXh0Q29udGVudCsxKTt9OwogZnVuY3Rpb24gdmlkKCl7cmV0dXJuIHNlbD9zZWwubGFiZWw6Jyc7fQogJCgnI2FkZENhcnQnKS5vbmNsaWNrPSgpPT57aWYocC52YXJpYW50cy5sZW5ndGgmJiFzZWwpe3RvYXN0KCfgpq3gp4fgprDgpr/gpq/gprzgp4fgpqjgp43gpp8g4Kas4KeH4Kab4KeHIOCmqOCmv+CmqCcpO3JldHVybjt9Q2FydC5hZGQocC5pZCx2aWQoKSwrJCgnI3F2JykudGV4dENvbnRlbnQpO3RvYXN0KCfgppXgpr7gprDgp43gpp/gp4cg4Kav4KeL4KaXIOCmueCmr+CmvOCnh+Cmm+CnhyDinJMnKTt9OwogJCgnI2J1eU5vdycpLm9uY2xpY2s9KCk9PntpZihwLnZhcmlhbnRzLmxlbmd0aCYmIXNlbCl7dG9hc3QoJ+CmreCnh+CmsOCmv+Cmr+CmvOCnh+CmqOCnjeCmnyDgpqzgp4fgppvgp4cg4Kao4Ka/4KaoJyk7cmV0dXJuO31DYXJ0LmFkZChwLmlkLHZpZCgpLCskKCcjcXYnKS50ZXh0Q29udGVudCk7Um91dGVyLmdvKCcvY2hlY2tvdXQnKTt9OwogZnVuY3Rpb24gcmVuZGVyVGFiKHQpewogICQoJyN0YWJCb2R5JykuaW5uZXJIVE1MPXQ9PT0ncyc/YDx0YWJsZSBjbGFzcz0ic3BlY3RhYmxlIj4ke3Auc3BlY3MubWFwKChbayx2XSk9PmA8dHI+PHRkPiR7ZXNjKGspfTwvdGQ+PHRkPiR7ZXNjKHYpfTwvdGQ+PC90cj5gKS5qb2luKCcnKX08L3RhYmxlPmA6YDxkaXYgY2xhc3M9InBkLWRlc2MiPiR7ZXNjKHAuZGVzY3x8J+Cmj+CmhyDgpqrgpqPgp43gpq/gp4fgprAg4Kas4Ka/4Ka44KeN4Kak4Ka+4Kaw4Ka/4KakIOCmrOCmv+CmrOCmsOCmoyDgprbgp4Dgppjgp43gprDgpocg4Kav4KeL4KaXIOCmleCmsOCmviDgprngpqzgp4fgpaQnKX08L2Rpdj5gOwogfQogcmVuZGVyVGFiKCdkJyk7CiBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudGFiczIgYnV0dG9uJykuZm9yRWFjaChiPT5iLm9uY2xpY2s9KCk9Pntkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudGFiczIgYnV0dG9uJykuZm9yRWFjaCh4PT54LmNsYXNzTGlzdC5yZW1vdmUoJ29uJykpO2IuY2xhc3NMaXN0LmFkZCgnb24nKTtyZW5kZXJUYWIoYi5kYXRhc2V0LnQpO30pOwp9KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpqrgp4fgppwgKGFib3V0L3Rlcm1zL3JldHVybnMvcHJpdmFjeSkKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovClJvdXRlci5hZGQoL15cL3BhZ2VcLyhcdyspJC8sIGFzeW5jIG09PnsKIGF3YWl0IGVuc3VyZUNmZygpOwogY29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvcGFnZS8nK21bMV0pOwogcm9vdC5pbm5lckhUTUw9bGF5b3V0KGA8ZGl2IGNsYXNzPSJ3cmFwIHN0YXRpYy1wYWdlIj48aDE+JHtlc2MoZC50aXRsZSl9PC9oMT48ZGl2IGNsYXNzPSJib2R5Ij4ke2VzYyhkLmJvZHkpfTwvZGl2PjwvZGl2PmApOwogYmluZExheW91dCgpOwp9KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpprgp4fgppXgpobgpongpp8KICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovClJvdXRlci5hZGQoL15cL2NoZWNrb3V0JC8sIGFzeW5jKCk9PnsKIGF3YWl0IGVuc3VyZUNmZygpOwogcm9vdC5pbm5lckhUTUw9bGF5b3V0KGA8ZGl2IGNsYXNzPSJ3cmFwIj48ZGl2IGlkPSJja1Jvb3QiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PjwvZGl2PmApOwogYmluZExheW91dCgpOwogYXdhaXQgcmVuZGVyQ2hlY2tvdXQoKTsKfSk7CmFzeW5jIGZ1bmN0aW9uIHJlbmRlckNoZWNrb3V0KCl7CiBjb25zdCBSPSQoJyNja1Jvb3QnKTsKIGlmKCFDYXJ0Lml0ZW1zLmxlbmd0aCl7Ui5pbm5lckhUTUw9JzxkaXYgY2xhc3M9ImVtcHR5Ij7wn5uSPHA+4KaV4Ka+4Kaw4KeN4KafIOCmluCmvuCmsuCmvyDigJQg4KaG4KaX4KeHIOCmquCmo+CnjeCmryDgpq/gp4vgppcg4KaV4Kaw4KeB4KaoPC9wPjxhIGNsYXNzPSJidG4iIGhyZWY9Ii9zaG9wIj7gppXgp4fgpqjgpr7gppXgpr7gpp/gpr4g4KaV4Kaw4KeB4KaoPC9hPjwvZGl2Pic7cmV0dXJuO30KIGxldCBkYXRhO3RyeXtkYXRhPWF3YWl0IGFwaSgnL2FwaS9jYXJ0Jyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtpdGVtczpDYXJ0Lml0ZW1zfSl9KTt9Y2F0Y2goZSl7Ui5pbm5lckhUTUw9ZXJyQm94KGUubWVzc2FnZSk7cmV0dXJuO30KIGNvbnN0IGJhZD1kYXRhLmxpbmVzLmZpbHRlcihsPT4hbC5vayk7CiBpZihiYWQubGVuZ3RoKXtiYWQuZm9yRWFjaChsPT57aWYobC5zdG9jazw9MClDYXJ0LnJlbW92ZShsLnBpZCxsLnZpZCk7fSk7Q2FydC5zYXZlKCk7fQogY29uc3QgbGluZXM9ZGF0YS5saW5lcy5maWx0ZXIobD0+bC5vayk7CiBpZighbGluZXMubGVuZ3RoKXtSLmlubmVySFRNTD0nPGRpdiBjbGFzcz0iZW1wdHkiPvCfmJU8cD7gppXgpr7gprDgp43gpp/gp4fgprAg4Kaq4Kaj4KeN4Kav4KaX4KeB4Kay4KeLIOCmhuCmsCDgpqrgpr7gppPgpq/gprzgpr4g4Kav4Ka+4Kaa4KeN4Kab4KeHIOCmqOCmvjwvcD48YSBjbGFzcz0iYnRuIiBocmVmPSIvc2hvcCI+4KaV4KeH4Kao4Ka+4KaV4Ka+4Kaf4Ka+IOCmleCmsOCngeCmqDwvYT48L2Rpdj4nO3JldHVybjt9CiBjb25zdCBzdWI9bGluZXMucmVkdWNlKChzLGwpPT5zK2wucHJpY2UqbC5xdHksMCk7CiBjb25zdCBwYXk9Q0ZHLnBheTsKIFIuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJja3dyYXAiPgogIDxkaXY+CiAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Kag4Ka/4KaV4Ka+4Kao4Ka+PC9oMz4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmquCngeCmsOCniyDgpqjgpr7gpq4gKjwvc3Bhbj48aW5wdXQgaWQ9ImZfbmFtZSIgbWF4bGVuZ3RoPSI4MCI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpq7gp4vgpqzgpr7gpofgprIg4Kao4Kau4KeN4Kas4KawICo8L3NwYW4+PGlucHV0IGlkPSJmX3Bob25lIiBtYXhsZW5ndGg9IjE0IiBpbnB1dG1vZGU9InRlbCIgcGxhY2Vob2xkZXI9IjAxWFhYWFhYWFhYIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmnOCnh+CmsuCmviAqPC9zcGFuPjxzZWxlY3QgaWQ9ImZfZGlzdCI+PG9wdGlvbiB2YWx1ZT0iIj7gpqzgp4fgppvgp4cg4Kao4Ka/4KaoPC9vcHRpb24+JHtDRkcuZGlzdHJpY3RzLm1hcChkPT5gPG9wdGlvbj4ke2VzYyhkKX08L29wdGlvbj5gKS5qb2luKCcnKX08L3NlbGVjdD48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmrOCmv+CmuOCnjeCmpOCmvuCmsOCmv+CmpCDgpqDgpr/gppXgpr7gpqjgpr4gKjwvc3Bhbj48dGV4dGFyZWEgaWQ9ImZfYWRkciIgbWF4bGVuZ3RoPSIzMDAiIHBsYWNlaG9sZGVyPSLgpqzgpr7gprjgpr4v4Kaw4KeL4KahL+Cmj+CmsuCmvuCmleCmviI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmheCmsOCnjeCmoeCmvuCmsCDgpqjgp4vgpp8gKOCmkOCmmuCnjeCmm+Cmv+CmlSk8L3NwYW4+PGlucHV0IGlkPSJmX25vdGUiIG1heGxlbmd0aD0iMzAwIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImhvbmV5cG90IiBhcmlhLWhpZGRlbj0idHJ1ZSI+PGlucHV0IGlkPSJmX2hwIiB0YWJpbmRleD0iLTEiIGF1dG9jb21wbGV0ZT0ib2ZmIj48L2Rpdj4KICAgPC9kaXY+CiAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqrgp4fgpq7gp4fgpqjgp43gpp8g4Kaq4Kam4KeN4Kan4Kak4Ka/PC9oMz48ZGl2IGlkPSJwYXlCb3giPgogICAgJHtwYXkuY29kP2A8bGFiZWwgY2xhc3M9InBheW9wdCBvbiIgZGF0YS12PSJjb2QiPjxpbnB1dCB0eXBlPSJyYWRpbyIgbmFtZT0icGF5IiB2YWx1ZT0iY29kIiBjaGVja2VkPjxzcGFuPjxiPuCmleCnjeCmr+CmvuCmtiDgpoXgpqgg4Kah4KeH4Kay4Ka/4Kat4Ka+4Kaw4Ka/PC9iPjxzbWFsbD7gpqrgpqPgp43gpq8g4Ka54Ka+4Kak4KeHIOCmquCnh+Cmr+CmvOCnhyDgpp/gpr7gppXgpr4g4Kam4Ka/4KaoPC9zbWFsbD48L3NwYW4+PC9sYWJlbD5gOicnfQogICAgJHtwYXkuYmthc2g/YDxsYWJlbCBjbGFzcz0icGF5b3B0IiBkYXRhLXY9ImJrYXNoIj48aW5wdXQgdHlwZT0icmFkaW8iIG5hbWU9InBheSIgdmFsdWU9ImJrYXNoIiR7cGF5LmNvZD8nJzonIGNoZWNrZWQnfT48c3Bhbj48Yj7gpqzgpr/gppXgpr7gprY8L2I+PHNtYWxsPlNlbmQgTW9uZXk6ICR7ZXNjKHBheS5ia2FzaCl9PC9zbWFsbD48L3NwYW4+PC9sYWJlbD5gOicnfQogICAgJHtwYXkubmFnYWQ/YDxsYWJlbCBjbGFzcz0icGF5b3B0IiBkYXRhLXY9Im5hZ2FkIj48aW5wdXQgdHlwZT0icmFkaW8iIG5hbWU9InBheSIgdmFsdWU9Im5hZ2FkIiR7KHBheS5jb2R8fHBheS5ia2FzaCk/Jyc6JyBjaGVja2VkJ30+PHNwYW4+PGI+4Kao4KaX4KamPC9iPjxzbWFsbD5TZW5kIE1vbmV5OiAke2VzYyhwYXkubmFnYWQpfTwvc21hbGw+PC9zcGFuPjwvbGFiZWw+YDonJ30KICAgIDwvZGl2PgogICAgPGRpdiBpZD0icGF5RXh0cmEiPjwvZGl2PgogICAgJHtwYXkubm90ZT9gPHAgc3R5bGU9ImZvbnQtc2l6ZToxMi41cHg7Y29sb3I6dmFyKC0tbXUpO21hcmdpbi10b3A6OHB4Ij4ke2VzYyhwYXkubm90ZSl9PC9wPmA6Jyd9CiAgIDwvZGl2PgogIDwvZGl2PgogIDxkaXY+CiAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpoXgprDgp43gpqHgpr7gprAg4Ka44Ka+4Kaw4Ka+4KaC4Ka2PC9oMz4KICAgIDxkaXYgaWQ9ImNrSXRlbXMiPiR7bGluZXMubWFwKGw9PmA8ZGl2IGNsYXNzPSJjaXRlbSI+PHNwYW4gc3R5bGU9IndpZHRoOjIycHg7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tbXUpIj4ke2wucXR5fcOXPC9zcGFuPgogICAgIDxkaXYgY2xhc3M9ImNpLWIiPjxkaXYgY2xhc3M9ImNpLXQiPiR7ZXNjKGwudGl0bGUpfTwvZGl2PiR7bC52aWQ/YDxkaXYgY2xhc3M9ImNpLXYiPiR7ZXNjKGwudmlkKX08L2Rpdj5gOicnfTwvZGl2PjxkaXYgY2xhc3M9ImNpLXByaWNlIj4ke21vbmV5KGwucHJpY2UqbC5xdHkpfTwvZGl2PjwvZGl2PmApLmpvaW4oJycpfTwvZGl2PgogICAgPGRpdiBjbGFzcz0iY291cG9ucm93IiBzdHlsZT0ibWFyZ2luLXRvcDoxMnB4Ij48aW5wdXQgaWQ9ImNwSW5wdXQiIHBsYWNlaG9sZGVyPSLgppXgp4Hgpqrgpqgg4KaV4KeL4KahIiBtYXhsZW5ndGg9IjIwIj48YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJjcEFwcGx5Ij7gpqrgp43gprDgpq/gprzgp4vgppc8L2J1dHRvbj48L2Rpdj4KICAgIDxwIGlkPSJjcE1zZyIgc3R5bGU9ImZvbnQtc2l6ZToxMi41cHg7bWFyZ2luOjRweCAwIDAiPjwvcD4KICAgIDxkaXYgaWQ9InN1bUJveCIgc3R5bGU9Im1hcmdpbi10b3A6MTJweCI+PC9kaXY+CiAgIDwvZGl2PgogIDwvZGl2PgogPC9kaXY+CiA8ZGl2IGNsYXNzPSJzdGlja3liYXIiPjxkaXYgc3R5bGU9ImZsZXg6MSI+PHNtYWxsIHN0eWxlPSJjb2xvcjp2YXIoLS1tdSkiPuCmuOCmsOCnjeCmrOCmruCni+Cmnzwvc21hbGw+PGJyPjxiIGlkPSJzdGlja3lUb3RhbCI+JHttb25leShzdWIpfTwvYj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJidG4gYmlnIiBpZD0icGxhY2VCdG4iPuCmheCmsOCnjeCmoeCmvuCmsCDgpqjgpr/gprbgp43gpprgpr/gpqQg4KaV4Kaw4KeB4KaoPC9idXR0b24+PC9kaXY+YDsKCiBsZXQgc2hpcENvc3Q9MDsKIGZ1bmN0aW9uIGNhbGNTaGlwKGRpc3Qpe2NvbnN0IFM9Q0ZHLnNob3A7Y29uc3QgYz1kaXN0PT09J+CmouCmvuCmleCmvic/K1Muc2hpcF9kaGFrYTorUy5zaGlwX291dHNpZGU7Y29uc3QgZnJlZT0rUy5mcmVlX292ZXI7cmV0dXJuKGZyZWU+MCYmc3ViPj1mcmVlKT8wOmM7fQogZnVuY3Rpb24gcmVuZGVyU3VtKCl7CiAgc2hpcENvc3Q9Y2FsY1NoaXAoJCgnI2ZfZGlzdCcpLnZhbHVlKTsKICBjb25zdCBkaXNjPUNPVVBPTj9DT1VQT04uZGlzY291bnQ6MDsKICBjb25zdCB0b3RhbD1NYXRoLm1heCgwLHN1Yi1kaXNjK3NoaXBDb3N0KTsKICAkKCcjc3VtQm94JykuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJzdW1yb3ciPjxzcGFuPuCmuOCmvuCmrOCmn+Cni+Cmn+CmvuCmsjwvc3Bhbj48c3Bhbj4ke21vbmV5KHN1Yil9PC9zcGFuPjwvZGl2PgogICAke2Rpc2M/YDxkaXYgY2xhc3M9InN1bXJvdyIgc3R5bGU9ImNvbG9yOnZhcigtLW9rKSI+PHNwYW4+4KaV4KeB4Kaq4KaoIOCmm+CmvuCmoeCmvCAoJHtlc2MoQ09VUE9OLmNvZGUpfSk8L3NwYW4+PHNwYW4+4oiSJHttb25leShkaXNjKX08L3NwYW4+PC9kaXY+YDonJ30KICAgPGRpdiBjbGFzcz0ic3Vtcm93Ij48c3Bhbj7gpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Kaa4Ka+4Kaw4KeN4KacPC9zcGFuPjxzcGFuPiR7c2hpcENvc3Q/bW9uZXkoc2hpcENvc3QpOifgpqvgp43gprDgpr8nfTwvc3Bhbj48L2Rpdj4KICAgPGRpdiBjbGFzcz0ic3Vtcm93IHRvdCI+PHNwYW4+4Ka44Kaw4KeN4Kas4Kau4KeL4KafPC9zcGFuPjxiPiR7bW9uZXkodG90YWwpfTwvYj48L2Rpdj5gOwogICQoJyNzdGlja3lUb3RhbCcpLnRleHRDb250ZW50PW1vbmV5KHRvdGFsKTsKIH0KIHJlbmRlclN1bSgpOwogJCgnI2ZfZGlzdCcpLm9uY2hhbmdlPXJlbmRlclN1bTsKICQoJyNjcEFwcGx5Jykub25jbGljaz1hc3luYygpPT57CiAgY29uc3QgY29kZT0kKCcjY3BJbnB1dCcpLnZhbHVlLnRyaW0oKTsKICBpZighY29kZSlyZXR1cm47CiAgJCgnI2NwTXNnJykudGV4dENvbnRlbnQ9J+Cmr+CmvuCmmuCmvuCmhyDgprngpprgp43gppvgp4figKYnOyQoJyNjcE1zZycpLnN0eWxlLmNvbG9yPSd2YXIoLS1tdSknOwogIHRyeXtjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9jb3Vwb24nLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2NvZGUsc3VidG90YWw6c3VifSl9KTtDT1VQT049ZDskKCcjY3BNc2cnKS50ZXh0Q29udGVudD0n4pyTIOCmleCngeCmquCmqCDgpqrgp43gprDgpq/gprzgp4vgppcg4Ka54Kav4Ka84KeH4Kab4KeHJzskKCcjY3BNc2cnKS5zdHlsZS5jb2xvcj0ndmFyKC0tb2spJztyZW5kZXJTdW0oKTt9CiAgY2F0Y2goZSl7Q09VUE9OPW51bGw7JCgnI2NwTXNnJykudGV4dENvbnRlbnQ9ZS5tZXNzYWdlOyQoJyNjcE1zZycpLnN0eWxlLmNvbG9yPSd2YXIoLS1iYWQpJztyZW5kZXJTdW0oKTt9CiB9OwogZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnBheW9wdCcpLmZvckVhY2gobz0+by5vbmNsaWNrPSgpPT57ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnBheW9wdCcpLmZvckVhY2goeD0+eC5jbGFzc0xpc3QucmVtb3ZlKCdvbicpKTtvLmNsYXNzTGlzdC5hZGQoJ29uJyk7by5xdWVyeVNlbGVjdG9yKCdpbnB1dCcpLmNoZWNrZWQ9dHJ1ZTtyZW5kZXJQYXlFeHRyYSgpO30pOwogZnVuY3Rpb24gcmVuZGVyUGF5RXh0cmEoKXsKICBjb25zdCB2PWRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ2lucHV0W25hbWU9cGF5XTpjaGVja2VkJykudmFsdWU7CiAgJCgnI3BheUV4dHJhJykuaW5uZXJIVE1MPXY9PT0nY29kJz8nJzpgPGRpdiBjbGFzcz0iZiIgc3R5bGU9Im1hcmdpbi10b3A6MTBweCI+PHNwYW4+VHJhbnNhY3Rpb24gSUQgKFRyeElEKSAqPC9zcGFuPjxpbnB1dCBpZD0iZl90cngiIG1heGxlbmd0aD0iMjAiIHN0eWxlPSJ0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2UiPjwvZGl2PgogICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpq/gp4cg4Kao4Kau4KeN4Kas4KawIOCmpeCnh+CmleCnhyDgprjgp4fgpqjgp43gpqEg4KaV4Kaw4KeH4Kab4KeH4KaoICo8L3NwYW4+PGlucHV0IGlkPSJmX3NlbmRlciIgbWF4bGVuZ3RoPSIxNCIgaW5wdXRtb2RlPSJ0ZWwiPjwvZGl2PmA7CiB9CiByZW5kZXJQYXlFeHRyYSgpOwoKIGZ1bmN0aW9uIG1hcmtFcnIoaWQsbXNnKXtjb25zdCBuPSQoaWQpO24uY2xhc3NMaXN0LmFkZCgnZi1lcnInKTtsZXQgZT1uLnBhcmVudEVsZW1lbnQucXVlcnlTZWxlY3RvcignLmVycnRleHQnKTtpZighZSl7ZT1lbCgnZGl2Jyx7Y2xhc3M6J2VycnRleHQnfSk7bi5wYXJlbnRFbGVtZW50LmFwcGVuZENoaWxkKGUpO31lLnRleHRDb250ZW50PW1zZzt9CiBmdW5jdGlvbiBjbGVhckVycigpe2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5mLWVycicpLmZvckVhY2gobj0+bi5jbGFzc0xpc3QucmVtb3ZlKCdmLWVycicpKTtkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcuZXJydGV4dCcpLmZvckVhY2gobj0+bi5yZW1vdmUoKSk7fQoKICQoJyNwbGFjZUJ0bicpLm9uY2xpY2s9YXN5bmMoKT0+ewogIGNsZWFyRXJyKCk7CiAgY29uc3QgbmFtZT0kKCcjZl9uYW1lJykudmFsdWUudHJpbSgpLCBwaG9uZT0kKCcjZl9waG9uZScpLnZhbHVlLnRyaW0oKSwgZGlzdD0kKCcjZl9kaXN0JykudmFsdWUsIGFkZHI9JCgnI2ZfYWRkcicpLnZhbHVlLnRyaW0oKTsKICBsZXQgYmFkPWZhbHNlOwogIGlmKG5hbWUubGVuZ3RoPDIpe21hcmtFcnIoJyNmX25hbWUnLCfgprjgpqDgpr/gppUg4Kao4Ka+4KauIOCmpuCmv+CmqCcpO2JhZD10cnVlO30KICBpZighL14wMVszLTldXGR7OH0kLy50ZXN0KHBob25lLnJlcGxhY2UoL1xEL2csJycpKSl7bWFya0VycignI2ZfcGhvbmUnLCfgprjgpqDgpr/gppUg4Kau4KeL4Kas4Ka+4KaH4KayIOCmqOCmruCnjeCmrOCmsCDgpqbgpr/gpqgnKTtiYWQ9dHJ1ZTt9CiAgaWYoIWRpc3Qpe21hcmtFcnIoJyNmX2Rpc3QnLCfgppzgp4fgprLgpr4g4Kas4KeH4Kab4KeHIOCmqOCmv+CmqCcpO2JhZD10cnVlO30KICBpZihhZGRyLmxlbmd0aDw4KXttYXJrRXJyKCcjZl9hZGRyJywn4Kag4Ka/4KaV4Ka+4Kao4Ka+IOCmhuCmsOCmkyDgpqzgpr/gprjgp43gpqTgpr7gprDgpr/gpqQg4Kay4Ka/4KaW4KeB4KaoJyk7YmFkPXRydWU7fQogIGNvbnN0IHBheXY9ZG9jdW1lbnQucXVlcnlTZWxlY3RvcignaW5wdXRbbmFtZT1wYXldOmNoZWNrZWQnKS52YWx1ZTsKICBsZXQgdHJ4PScnLHNlbmRlcj0nJzsKICBpZihwYXl2IT09J2NvZCcpewogICB0cng9KCQoJyNmX3RyeCcpPy52YWx1ZXx8JycpLnRyaW0oKS50b1VwcGVyQ2FzZSgpO3NlbmRlcj0oJCgnI2Zfc2VuZGVyJyk/LnZhbHVlfHwnJykudHJpbSgpOwogICBpZighL15bQS1aMC05XXs2LDIwfSQvLnRlc3QodHJ4KSl7bWFya0VycignI2ZfdHJ4Jywn4Ka44Kag4Ka/4KaVIFRyeElEIOCmpuCmv+CmqCcpO2JhZD10cnVlO30KICAgaWYoIS9eMDFbMy05XVxkezh9JC8udGVzdChzZW5kZXIucmVwbGFjZSgvXEQvZywnJykpKXttYXJrRXJyKCcjZl9zZW5kZXInLCfgprjgpqDgpr/gppUg4Kao4Kau4KeN4Kas4KawIOCmpuCmv+CmqCcpO2JhZD10cnVlO30KICB9CiAgaWYoYmFkKXt0b2FzdCgn4Kak4Kal4KeN4Kav4KaX4KeB4Kay4KeLIOCmhuCmrOCmvuCmsCDgpqbgp4fgppbgp4HgpqgnKTtkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcuZi1lcnInKT8uc2Nyb2xsSW50b1ZpZXcoe2Jsb2NrOidjZW50ZXInfSk7cmV0dXJuO30KICBjb25zdCBidG49JCgnI3BsYWNlQnRuJyk7YnRuLmRpc2FibGVkPXRydWU7YnRuLnRleHRDb250ZW50PSfgpoXgprDgp43gpqHgpr7gprAg4Ka54Kaa4KeN4Kab4KeH4oCmJzsKICBpZighcGxhY2VDaGVja291dC5pZGVtKXBsYWNlQ2hlY2tvdXQuaWRlbT1NYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyKStEYXRlLm5vdygpOwogIHRyeXsKICAgY29uc3QgcmVzPWF3YWl0IGFwaSgnL2FwaS9vcmRlcicse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7bmFtZSxwaG9uZSxkaXN0cmljdDpkaXN0LGFkZHJlc3M6YWRkcixub3RlOiQoJyNmX25vdGUnKS52YWx1ZS50cmltKCksCiAgICBwYXltZW50OnBheXYscGF5X3JlZjp0cngscGF5X3NlbmRlcjpzZW5kZXIsaXRlbXM6Q2FydC5pdGVtcyxjb3Vwb246Q09VUE9OP0NPVVBPTi5jb2RlOicnLGlkZW06cGxhY2VDaGVja291dC5pZGVtLGhwOiQoJyNmX2hwJykudmFsdWV9KX0pOwogICBDYXJ0LmNsZWFyKCk7Q09VUE9OPW51bGw7CiAgIFJvdXRlci5nbygnL29yZGVyLycrcmVzLmNvZGUsdHJ1ZSk7CiAgfWNhdGNoKGUpe3RvYXN0KGUubWVzc2FnZSk7YnRuLmRpc2FibGVkPWZhbHNlO2J0bi50ZXh0Q29udGVudD0n4KaF4Kaw4KeN4Kah4Ka+4KawIOCmqOCmv+CmtuCnjeCmmuCmv+CmpCDgppXgprDgp4HgpqgnO30KIH07Cn0KZnVuY3Rpb24gcGxhY2VDaGVja291dCgpe30KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpoXgprDgp43gpqHgpr7gprAg4Ka44Kar4KayCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpSb3V0ZXIuYWRkKC9eXC9vcmRlclwvKFtBLVphLXowLTktXSspJC8sIGFzeW5jIG09PnsKIGF3YWl0IGVuc3VyZUNmZygpOwogcm9vdC5pbm5lckhUTUw9bGF5b3V0KGA8ZGl2IGNsYXNzPSJ3cmFwIGNlbnRlci1ib3giPgogIDxkaXYgY2xhc3M9Im9raWNvbiI+4pyTPC9kaXY+PGgxIHN0eWxlPSJmb250LXNpemU6MjBweCI+4KaF4Kaw4KeN4Kah4Ka+4Kaw4Kaf4Ka/IOCmuOCmq+CmsiDgprngpq/gprzgp4fgppvgp4chPC9oMT4KICA8cCBzdHlsZT0iY29sb3I6dmFyKC0tbXUpIj7gpobgpqrgpqjgpr7gprAg4KaF4Kaw4KeN4Kah4Ka+4KawIOCmleCni+CmoTwvcD48ZGl2IGNsYXNzPSJjb2RlYm94Ij4ke2VzYyhtWzFdKX08L2Rpdj4KICA8cCBzdHlsZT0iY29sb3I6dmFyKC0tbXUpO2ZvbnQtc2l6ZToxMy41cHgiPuCmj+CmhyDgppXgp4vgpqHgpp/gpr8g4Ka44KaC4Kaw4KaV4KeN4Ka34KajIOCmleCmsOCngeCmqCDigJQg4KaF4Kaw4KeN4Kah4Ka+4Kaw4KeH4KawIOCmheCmrOCmuOCnjeCmpeCmviDgppzgpr7gpqjgpqTgp4cg4KaV4Ka+4Kac4KeHIOCmsuCmvuCml+CmrOCnh+ClpDwvcD4KICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7anVzdGlmeS1jb250ZW50OmNlbnRlcjttYXJnaW4tdG9wOjE2cHg7ZmxleC13cmFwOndyYXAiPgogICA8YSBjbGFzcz0iYnRuIiBocmVmPSIvdHJhY2s/Y29kZT0ke2VuY29kZVVSSUNvbXBvbmVudChtWzFdKX0iPuCmheCmsOCnjeCmoeCmvuCmsCDgpqbgp4fgppbgp4Hgpqg8L2E+PGEgY2xhc3M9ImJ0biBnaG9zdCIgaHJlZj0iL3Nob3AiPuCmleCnh+CmqOCmvuCmleCmvuCmn+CmviDgpprgpr7gprLgpr/gpq/gprzgp4cg4Kav4Ka+4KaoPC9hPjwvZGl2PgogPC9kaXY+YCk7CiBiaW5kTGF5b3V0KCk7Cn0pOwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmheCmsOCnjeCmoeCmvuCmsCDgpp/gp43gprDgp43gpq/gpr7gppUKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmNvbnN0IFNUTEFCRUw9e3BlbmRpbmc6J+Cml+Cng+CmueCngOCmpCDgprngpq/gprzgp4fgppvgp4cnLGNvbmZpcm1lZDon4Kao4Ka/4Ka24KeN4Kaa4Ka/4KakIOCmueCmr+CmvOCnh+Cmm+CnhycscHJvY2Vzc2luZzon4Kaq4KeN4Kaw4Ka44KeN4Kak4KeB4KakIOCmueCmmuCnjeCmm+Cnhycsc2hpcHBlZDon4Kaq4Ka+4Kag4Ka+4Kao4KeLIOCmueCmr+CmvOCnh+Cmm+CnhycsZGVsaXZlcmVkOifgpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Ka54Kav4Ka84KeH4Kab4KeHJyxjYW5jZWxsZWQ6J+CmrOCmvuCmpOCmv+CmsiDgprngpq/gprzgp4fgppvgp4cnLHJldHVybmVkOifgpqvgp4fgprDgpqQg4Ka54Kav4Ka84KeH4Kab4KeHJ307CmNvbnN0IFNUT1JERVI9WydwZW5kaW5nJywnY29uZmlybWVkJywncHJvY2Vzc2luZycsJ3NoaXBwZWQnLCdkZWxpdmVyZWQnXTsKUm91dGVyLmFkZCgvXlwvdHJhY2skLywgYXN5bmMobSxxKT0+ewogYXdhaXQgZW5zdXJlQ2ZnKCk7CiByb290LmlubmVySFRNTD1sYXlvdXQoYDxkaXYgY2xhc3M9IndyYXAiIHN0eWxlPSJtYXgtd2lkdGg6NTYwcHg7bWFyZ2luOjAgYXV0bztwYWRkaW5nLXRvcDoyMHB4Ij4KICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4KaF4Kaw4KeN4Kah4Ka+4KawIOCmn+CnjeCmsOCnjeCmr+CmvuCmlSDgppXgprDgp4Hgpqg8L2gzPgogICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpoXgprDgp43gpqHgpr7gprAg4KaV4KeL4KahPC9zcGFuPjxpbnB1dCBpZD0idGNfY29kZSIgdmFsdWU9IiR7ZXNjKHEuY29kZXx8JycpfSIgcGxhY2Vob2xkZXI9IkRLLVhYWFhYWFhYIiBzdHlsZT0idGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kau4KeL4Kas4Ka+4KaH4KayIOCmqOCmruCnjeCmrOCmsDwvc3Bhbj48aW5wdXQgaWQ9InRjX3Bob25lIiBwbGFjZWhvbGRlcj0iMDFYWFhYWFhYWFgiPjwvZGl2PgogICA8YnV0dG9uIGNsYXNzPSJidG4gYmxvY2siIGlkPSJ0Y19nbyI+4KaW4KeB4KaB4Kac4KeB4KaoPC9idXR0b24+PC9kaXY+CiAgPGRpdiBpZD0idGNfcmVzdWx0IiBzdHlsZT0ibWFyZ2luLXRvcDoxNnB4Ij48L2Rpdj48L2Rpdj5gKTsKIGJpbmRMYXlvdXQoKTsKIGFzeW5jIGZ1bmN0aW9uIGdvKCl7CiAgY29uc3QgY29kZT0kKCcjdGNfY29kZScpLnZhbHVlLnRyaW0oKSwgcGhvbmU9JCgnI3RjX3Bob25lJykudmFsdWUudHJpbSgpOwogIGlmKCFjb2RlfHwhcGhvbmUpe3RvYXN0KCfgppXgp4vgpqEg4KaTIOCmq+Cni+CmqCDgpqjgpq7gp43gpqzgprAg4Kam4Ka/4KaoJyk7cmV0dXJuO30KICAkKCcjdGNfcmVzdWx0JykuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJzcGluIj48L2Rpdj4nOwogIHRyeXtjb25zdCBvPWF3YWl0IGFwaSgnL2FwaS90cmFjaycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7Y29kZSxwaG9uZX0pfSk7cmVuZGVyVHJhY2sobyk7fQogIGNhdGNoKGUpeyQoJyN0Y19yZXN1bHQnKS5pbm5lckhUTUw9YDxwIGNsYXNzPSJlbXB0eSI+JHtlc2MoZS5tZXNzYWdlKX08L3A+YDt9CiB9CiAkKCcjdGNfZ28nKS5vbmNsaWNrPWdvOwogaWYocS5jb2RlKSQoJyN0Y19waG9uZScpLmZvY3VzKCk7Cn0pOwpmdW5jdGlvbiByZW5kZXJUcmFjayhvKXsKIGNvbnN0IGN1cj1TVE9SREVSLmluZGV4T2Yoby5zdGF0dXMpOwogY29uc3QgY2FuY2VsbGVkPW8uc3RhdHVzPT09J2NhbmNlbGxlZCd8fG8uc3RhdHVzPT09J3JldHVybmVkJzsKICQoJyN0Y19yZXN1bHQnKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9ImNhcmQiPgogIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbiI+PGI+JHtlc2Moby5jb2RlKX08L2I+PHNwYW4+JHtlc2MoU1RMQUJFTFtvLnN0YXR1c10pfTwvc3Bhbj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJ0aW1lbGluZSIgc3R5bGU9Im1hcmdpbi10b3A6MTZweCI+CiAgICR7Y2FuY2VsbGVkP2A8ZGl2IGNsYXNzPSJ0bC1pdGVtIGRvbmUiPjxkaXYgY2xhc3M9InRsLWRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tYmFkKSI+PC9kaXY+PGRpdiBjbGFzcz0idGwtYiI+PGI+JHtlc2MoU1RMQUJFTFtvLnN0YXR1c10pfTwvYj48L2Rpdj48L2Rpdj5gOgogICAgIFNUT1JERVIubWFwKChzLGkpPT5gPGRpdiBjbGFzcz0idGwtaXRlbSAke2k8PWN1cj8nZG9uZSc6Jyd9Ij48ZGl2IGNsYXNzPSJ0bC1kb3QiPjwvZGl2PjxkaXYgY2xhc3M9InRsLWIiPjxiPiR7ZXNjKFNUTEFCRUxbc10pfTwvYj4ke2k8PWN1cj9gPHNtYWxsPiR7by5ldmVudHMuZmlsdGVyKGU9PmUuc3RhdHVzPT09cykubWFwKGU9PnRpbWVGbXQoZS5jcmVhdGVkKSkuam9pbignJyl9PC9zbWFsbD5gOicnfTwvZGl2PjwvZGl2PmApLmpvaW4oJycpfQogIDwvZGl2PjwvZGl2PgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Kak4Kal4KeN4KavPC9oMz48cD4ke2VzYyhvLm5hbWUpfSDCtyAke2VzYyhvLmRpc3RyaWN0KX08L3A+PHAgc3R5bGU9ImNvbG9yOnZhcigtLW11KTtmb250LXNpemU6MTMuNXB4Ij4ke2VzYyhvLmFkZHJlc3MpfTwvcD48L2Rpdj4KICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Kaq4Kaj4KeN4Kav4Ka44Kau4KeC4Ka5PC9oMz4ke28uaXRlbXMubWFwKGk9PmA8ZGl2IGNsYXNzPSJjaXRlbSI+PHNwYW4gc3R5bGU9IndpZHRoOjIycHg7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tbXUpIj4ke2kucXR5fcOXPC9zcGFuPjxkaXYgY2xhc3M9ImNpLWIiPjxkaXYgY2xhc3M9ImNpLXQiPiR7ZXNjKGkudGl0bGUpfSR7aS52YXJpYW50P2AgKCR7ZXNjKGkudmFyaWFudCl9KWA6Jyd9PC9kaXY+PC9kaXY+PGRpdiBjbGFzcz0iY2ktcHJpY2UiPiR7bW9uZXkoaS5wcmljZSppLnF0eSl9PC9kaXY+PC9kaXY+YCkuam9pbignJyl9CiAgIDxkaXYgY2xhc3M9InN1bXJvdyI+PHNwYW4+4Ka44Ka+4Kas4Kaf4KeL4Kaf4Ka+4KayPC9zcGFuPjxzcGFuPiR7bW9uZXkoby5zdWJ0b3RhbCl9PC9zcGFuPjwvZGl2PgogICAke28uZGlzY291bnQ/YDxkaXYgY2xhc3M9InN1bXJvdyI+PHNwYW4+4Kab4Ka+4Kah4Ka8PC9zcGFuPjxzcGFuPuKIkiR7bW9uZXkoby5kaXNjb3VudCl9PC9zcGFuPjwvZGl2PmA6Jyd9CiAgIDxkaXYgY2xhc3M9InN1bXJvdyI+PHNwYW4+4Kah4KeH4Kay4Ka/4Kat4Ka+4Kaw4Ka/PC9zcGFuPjxzcGFuPiR7by5zaGlwcGluZz9tb25leShvLnNoaXBwaW5nKTon4Kar4KeN4Kaw4Ka/J308L3NwYW4+PC9kaXY+CiAgIDxkaXYgY2xhc3M9InN1bXJvdyB0b3QiPjxzcGFuPuCmuOCmsOCnjeCmrOCmruCni+Cmnzwvc3Bhbj48Yj4ke21vbmV5KG8udG90YWwpfTwvYj48L2Rpdj4KICAgPHAgc3R5bGU9ImZvbnQtc2l6ZToxMi41cHg7Y29sb3I6dmFyKC0tbXUpO21hcmdpbi10b3A6OHB4Ij7gpqrgp4fgpq7gp4fgpqjgp43gpp86ICR7by5wYXltZW50PT09J2NvZCc/J+CmleCnjeCmr+CmvuCmtiDgpoXgpqgg4Kah4KeH4Kay4Ka/4Kat4Ka+4Kaw4Ka/JzpvLnBheW1lbnQudG9VcHBlckNhc2UoKX0g4oCUICR7by5wYXlfc3RhdHVzPT09J3BhaWQnPyfgpqrgprDgpr/gprbgp4vgpqfgpr/gpqQnOifgpoXgpqrgprDgpr/gprbgp4vgpqfgpr/gpqQnfTwvcD48L2Rpdj5gOwp9CmZ1bmN0aW9uIHRpbWVGbXQodHMpe2NvbnN0IGQ9bmV3IERhdGUodHMqMTAwMCk7cmV0dXJuICcgwrcgJytkLnRvTG9jYWxlRGF0ZVN0cmluZygnYm4tQkQnLHtkYXk6J251bWVyaWMnLG1vbnRoOidzaG9ydCd9KSsnICcrZC50b0xvY2FsZVRpbWVTdHJpbmcoJ2JuLUJEJyx7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0J30pO30KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgprbgp4HgprDgp4EKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCihhc3luYyBmdW5jdGlvbiBpbml0KCl7CiB0cnl7YXdhaXQgZW5zdXJlQ2ZnKCk7fWNhdGNoKGUpe3Jvb3QuaW5uZXJIVE1MPWVyckJveCgn4Ka44Ka+4KaH4KafIOCmsuCni+CmoSDgppXgprDgpr4g4Kav4Ka+4Kav4Ka84Kao4Ka/4KWkIOCmj+CmleCmn+CngSDgpqrgprDgp4cg4KaG4Kas4Ka+4KawIOCmmuCnh+Cmt+CnjeCmn+CmviDgppXgprDgp4HgpqjgpaQnKTtyZXR1cm47fQogUm91dGVyLnJlbmRlcigpOwp9KSgpOwo=")
ADMIN_CSS = _b64("Kntib3gtc2l6aW5nOmJvcmRlci1ib3h9Cmh0bWwsYm9keXttYXJnaW46MDtoZWlnaHQ6MTAwJX0KYm9keXtiYWNrZ3JvdW5kOnZhcigtLWJnKTtjb2xvcjp2YXIoLS10eCk7Zm9udDo0MDAgMTQuNXB4LzEuNiAnSGluZCBTaWxpZ3VyaScsc3lzdGVtLXVpLHNhbnMtc2VyaWY7LXdlYmtpdC10YXAtaGlnaGxpZ2h0LWNvbG9yOnRyYW5zcGFyZW50fQo6cm9vdHstLWJnOiNGMUYyRjg7LS1zOiNmZmY7LS1zMjojRjRGNUZBOy0tbG46I0UzRTVGMDstLXR4OiMxODFCMkU7LS1tdTojNjY2QzhBOy0tYWM6IzJCM0JBODstLWFjLWw6I0VFRjBGRjstLW9rOiMwRThBNUY7LS1iYWQ6I0QyMjY0QTstLXdhcm46I0I4NzkwQX0KYnV0dG9uLGlucHV0LHNlbGVjdCx0ZXh0YXJlYXtmb250OmluaGVyaXQ7Y29sb3I6aW5oZXJpdH0KYnV0dG9ue2N1cnNvcjpwb2ludGVyfQphe2NvbG9yOmluaGVyaXQ7dGV4dC1kZWNvcmF0aW9uOm5vbmV9Cjpmb2N1cy12aXNpYmxle291dGxpbmU6MnB4IHNvbGlkIHZhcigtLWFjKTtvdXRsaW5lLW9mZnNldDoycHh9CmltZ3ttYXgtd2lkdGg6MTAwJX0KaDEsaDIsaDMsaDR7bWFyZ2luOjB9Cjo6LXdlYmtpdC1zY3JvbGxiYXJ7d2lkdGg6OHB4O2hlaWdodDo4cHh9Cjo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3VuZDp2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czo4cHh9CgovKiA9PT09PSDgprLgppfgpofgpqggPT09PT0gKi8KLmxvZ2lud3JhcHttaW4taGVpZ2h0OjEwMHZoO2Rpc3BsYXk6Z3JpZDtwbGFjZS1pdGVtczpjZW50ZXI7cGFkZGluZzoyMHB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE2MGRlZyx2YXIoLS1hYyksIzE1MTgzMyl9Ci5sb2dpbmNhcmR7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXItcmFkaXVzOjE4cHg7cGFkZGluZzozMHB4IDI2cHg7d2lkdGg6bWluKDM4MHB4LDEwMCUpO2JveC1zaGFkb3c6MCAyMHB4IDUwcHggcmdiYSgwLDAsMCwuMjUpfQoubG9naW5jYXJkIGgxe2ZvbnQtc2l6ZToyMHB4O21hcmdpbi1ib3R0b206NHB4fQoubG9naW5jYXJkIHAuc3Vie2NvbG9yOnZhcigtLW11KTtmb250LXNpemU6MTNweDttYXJnaW4tYm90dG9tOjIwcHh9Ci5me2Rpc3BsYXk6Z3JpZDtnYXA6NXB4O21hcmdpbi1ib3R0b206MTRweH0KLmY+c3Bhbntmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1tdSk7Zm9udC13ZWlnaHQ6NTAwfQouZiBpbnB1dCwuZiBzZWxlY3QsLmYgdGV4dGFyZWF7Ym9yZGVyOjEuNXB4IHNvbGlkIHZhcigtLWxuKTtib3JkZXItcmFkaXVzOjlweDtwYWRkaW5nOjEwcHggMTJweDtiYWNrZ3JvdW5kOnZhcigtLXMyKTt3aWR0aDoxMDAlfQouZiBpbnB1dDpmb2N1cywuZiBzZWxlY3Q6Zm9jdXMsLmYgdGV4dGFyZWE6Zm9jdXN7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXItY29sb3I6dmFyKC0tYWMpfQouZiB0ZXh0YXJlYXttaW4taGVpZ2h0OjgwcHg7cmVzaXplOnZlcnRpY2FsfQouZXJyYmFubmVye2JhY2tncm91bmQ6I0ZERUNFRjtjb2xvcjp2YXIoLS1iYWQpO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OXB4IDEycHg7Zm9udC1zaXplOjEzcHg7bWFyZ2luLWJvdHRvbToxMnB4fQoub2tiYW5uZXJ7YmFja2dyb3VuZDojRThGOEYxO2NvbG9yOnZhcigtLW9rKTtib3JkZXItcmFkaXVzOjlweDtwYWRkaW5nOjlweCAxMnB4O2ZvbnQtc2l6ZToxM3B4O21hcmdpbi1ib3R0b206MTJweH0KLmJ0bntiYWNrZ3JvdW5kOnZhcigtLWFjKTtjb2xvcjojZmZmO2JvcmRlcjowO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6MTFweCAxOHB4O2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MTRweH0KLmJ0bi5ibG9ja3t3aWR0aDoxMDAlfQouYnRuLmdob3N0e2JhY2tncm91bmQ6dmFyKC0tczIpO2NvbG9yOnZhcigtLWFjKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxuKX0KLmJ0bi5kYW5nZXJ7YmFja2dyb3VuZDojRkRFQ0VGO2NvbG9yOnZhcigtLWJhZCl9Ci5idG4uc217cGFkZGluZzo3cHggMTJweDtmb250LXNpemU6MTNweDtib3JkZXItcmFkaXVzOjdweH0KLmJ0bjpkaXNhYmxlZHtvcGFjaXR5Oi41NTtjdXJzb3I6bm90LWFsbG93ZWR9Ci5tdXRlZHtjb2xvcjp2YXIoLS1tdSl9CgovKiA9PT09PSDgpoXgp43gpq/gpr7gpqog4KaV4Ka+4Kag4Ka+4Kau4KeLID09PT09ICovCi5hcHB7ZGlzcGxheTpub25lO21pbi1oZWlnaHQ6MTAwdmh9Ci5hcHAub257ZGlzcGxheTpmbGV4fQouc2lkZXt3aWR0aDoyMzBweDtiYWNrZ3JvdW5kOiMxMjE0MkE7Y29sb3I6I0M2QzlFNjtmbGV4Om5vbmU7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtwb3NpdGlvbjpmaXhlZDt0b3A6MDtib3R0b206MDt0cmFuc2Zvcm06dHJhbnNsYXRlWCgtMTAwJSk7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjJzO3otaW5kZXg6NTB9Ci5zaWRlLm9ue3RyYW5zZm9ybTp0cmFuc2xhdGVYKDApfQouc2lkZS1oZHtwYWRkaW5nOjIwcHggMThweDtmb250OjcwMCAxOHB4ICdIaW5kIFNpbGlndXJpJztjb2xvcjojZmZmO2JvcmRlci1ib3R0b206MXB4IHNvbGlkICMyMzI2NGF9Ci5zaWRlIG5hdntmbGV4OjE7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MTBweH0KLnNpZGUgYXtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMXB4O3BhZGRpbmc6MTFweCAxMnB4O2JvcmRlci1yYWRpdXM6OXB4O2ZvbnQtc2l6ZToxNHB4O21hcmdpbi1ib3R0b206MnB4fQouc2lkZSBhIHN2Z3t3aWR0aDoxOHB4O2hlaWdodDoxOHB4O2ZpbGw6bm9uZTtzdHJva2U6Y3VycmVudENvbG9yO3N0cm9rZS13aWR0aDoxLjg7ZmxleDpub25lfQouc2lkZSBhOmhvdmVye2JhY2tncm91bmQ6IzFCMUUzQn0KLnNpZGUgYS5vbntiYWNrZ3JvdW5kOnZhcigtLWFjKTtjb2xvcjojZmZmfQouc2lkZSAuYmFkZ2Uye21hcmdpbi1sZWZ0OmF1dG87YmFja2dyb3VuZDp2YXIoLS1iYWQpO2NvbG9yOiNmZmY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7cGFkZGluZzoxcHggN3B4O2JvcmRlci1yYWRpdXM6MjBweH0KLnNpZGUtZnR7cGFkZGluZzoxNHB4O2JvcmRlci10b3A6MXB4IHNvbGlkICMyMzI2NGE7Zm9udC1zaXplOjEyLjVweH0KLm1haW57ZmxleDoxO21hcmdpbi1sZWZ0OjA7bWluLXdpZHRoOjB9CkBtZWRpYShtaW4td2lkdGg6OTYwcHgpey5zaWRle3Bvc2l0aW9uOnN0YXRpYzt0cmFuc2Zvcm06bm9uZX0ubWFpbnttYXJnaW4tbGVmdDowfX0KLnRvcGJ7cG9zaXRpb246c3RpY2t5O3RvcDowO3otaW5kZXg6MjA7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1sbik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweDtwYWRkaW5nOjEycHggMTZweH0KLnRvcGIgaDF7Zm9udC1zaXplOjE4cHh9Ci5idXJnZXJ7ZGlzcGxheTpmbGV4O3dpZHRoOjM2cHg7aGVpZ2h0OjM2cHg7Ym9yZGVyLXJhZGl1czo5cHg7YmFja2dyb3VuZDp2YXIoLS1zMik7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7ZmxleDpub25lfQpAbWVkaWEobWluLXdpZHRoOjk2MHB4KXsuYnVyZ2Vye2Rpc3BsYXk6bm9uZX19Ci5zY3JpbXtwb3NpdGlvbjpmaXhlZDtpbnNldDowO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwuNCk7ei1pbmRleDo0MDtkaXNwbGF5Om5vbmV9Ci5zY3JpbS5vbntkaXNwbGF5OmJsb2NrfQouY29udGVudHtwYWRkaW5nOjE2cHg7bWF4LXdpZHRoOjExODBweH0KCi8qID09PT09IOCmleCmvuCmsOCnjeCmoSwg4KaX4KeN4Kaw4Ka/4KahID09PT09ICovCi5jYXJke2JhY2tncm91bmQ6dmFyKC0tcyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czoxNHB4O3BhZGRpbmc6MTZweH0KLmNhcmQrLmNhcmR7bWFyZ2luLXRvcDoxNHB4fQouZ3JpZHtkaXNwbGF5OmdyaWQ7Z2FwOjE0cHh9Ci5nNHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDQsMWZyKX0KLmcye2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfQpAbWVkaWEobWF4LXdpZHRoOjc2MHB4KXsuZzR7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLDFmcil9Lmcye2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9fQouc3RhdHtiYWNrZ3JvdW5kOnZhcigtLXMpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbG4pO2JvcmRlci1yYWRpdXM6MTRweDtwYWRkaW5nOjE2cHh9Ci5zdGF0IGJ7ZGlzcGxheTpibG9jaztmb250LXNpemU6MjJweDttYXJnaW4tdG9wOjRweH0KLnN0YXQgLmxibHtjb2xvcjp2YXIoLS1tdSk7Zm9udC1zaXplOjEyLjVweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHh9Ci5zdGF0Lndhcm4gYntjb2xvcjp2YXIoLS13YXJuKX0KCi8qID09PT09IOCmn+Cnh+CmrOCmv+CmsiA9PT09PSAqLwoudGJsd3JhcHtvdmVyZmxvdy14OmF1dG99CnRhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO2ZvbnQtc2l6ZToxMy41cHg7bWluLXdpZHRoOjU2MHB4fQp0aHt0ZXh0LWFsaWduOnJpZ2h0O2NvbG9yOnZhcigtLW11KTtmb250LXdlaWdodDo2MDA7Zm9udC1zaXplOjEyLjVweDtwYWRkaW5nOjlweCA4cHg7Ym9yZGVyLWJvdHRvbToycHggc29saWQgdmFyKC0tbG4pO3doaXRlLXNwYWNlOm5vd3JhcH0KdGR7cGFkZGluZzoxMHB4IDhweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1sbik7dmVydGljYWwtYWxpZ246bWlkZGxlfQp0cjpob3ZlciB0ZHtiYWNrZ3JvdW5kOnZhcigtLXMyKX0KLnRhZ3tkaXNwbGF5OmlubGluZS1ibG9jaztwYWRkaW5nOjNweCA5cHg7Ym9yZGVyLXJhZGl1czo5OTlweDtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjcwMH0KLnRhZy5wZW5kaW5ne2JhY2tncm91bmQ6I0ZGRjNFMDtjb2xvcjp2YXIoLS13YXJuKX0KLnRhZy5jb25maXJtZWR7YmFja2dyb3VuZDojRTdFQ0ZGO2NvbG9yOnZhcigtLWFjKX0KLnRhZy5wcm9jZXNzaW5ne2JhY2tncm91bmQ6I0U3RUNGRjtjb2xvcjp2YXIoLS1hYyl9Ci50YWcuc2hpcHBlZHtiYWNrZ3JvdW5kOiNFMUY1RkU7Y29sb3I6IzAyNzdCRH0KLnRhZy5kZWxpdmVyZWR7YmFja2dyb3VuZDojRThGOEYxO2NvbG9yOnZhcigtLW9rKX0KLnRhZy5jYW5jZWxsZWQsLnRhZy5yZXR1cm5lZHtiYWNrZ3JvdW5kOiNGREVDRUY7Y29sb3I6dmFyKC0tYmFkKX0KLnRhZy5wYWlke2JhY2tncm91bmQ6I0U4RjhGMTtjb2xvcjp2YXIoLS1vayl9Ci50YWcudW5wYWlke2JhY2tncm91bmQ6I0ZERUNFRjtjb2xvcjp2YXIoLS1iYWQpfQoKLyogPT09PT0g4Kar4Kaw4KeN4KauLCDgpp/gp4HgprLgpqzgpr7gprAgPT09PT0gKi8KLnRvb2xiYXJ7ZGlzcGxheTpmbGV4O2dhcDo4cHg7ZmxleC13cmFwOndyYXA7YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbi1ib3R0b206MTRweH0KLnRvb2xiYXIgaW5wdXQsLnRvb2xiYXIgc2VsZWN0e2JvcmRlcjoxLjVweCBzb2xpZCB2YXIoLS1sbik7Ym9yZGVyLXJhZGl1czo5cHg7cGFkZGluZzo5cHggMTFweDtiYWNrZ3JvdW5kOnZhcigtLXMpfQoudG9vbGJhciAuZ3Jvd3tmbGV4OjE7bWluLXdpZHRoOjE2MHB4fQouY2hpcHtwYWRkaW5nOjZweCAxM3B4O2JvcmRlci1yYWRpdXM6OTk5cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1sbik7YmFja2dyb3VuZDp2YXIoLS1zKTtmb250LXNpemU6MTNweH0KLmNoaXAub257YmFja2dyb3VuZDp2YXIoLS1hYyk7Y29sb3I6I2ZmZjtib3JkZXItY29sb3I6dmFyKC0tYWMpfQouZjJ7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDoxMnB4fQpAbWVkaWEobWF4LXdpZHRoOjYwMHB4KXsuZjJ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19Ci5mLmNoa3tkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo5cHg7ZmxleC1kaXJlY3Rpb246cm93fQouZi5jaGsgaW5wdXR7d2lkdGg6MThweDtoZWlnaHQ6MThweDthY2NlbnQtY29sb3I6dmFyKC0tYWMpfQoucGFnZXJ7ZGlzcGxheTpmbGV4O2dhcDo2cHg7anVzdGlmeS1jb250ZW50OmNlbnRlcjttYXJnaW4tdG9wOjE2cHg7ZmxleC13cmFwOndyYXB9Ci5wYWdlciBidXR0b257d2lkdGg6MzRweDtoZWlnaHQ6MzRweDtib3JkZXItcmFkaXVzOjhweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxuKTtiYWNrZ3JvdW5kOnZhcigtLXMpfQoucGFnZXIgYnV0dG9uLm9ue2JhY2tncm91bmQ6dmFyKC0tYWMpO2NvbG9yOiNmZmY7Ym9yZGVyLWNvbG9yOnZhcigtLWFjKX0KLmVycnRleHR7Y29sb3I6dmFyKC0tYmFkKTtmb250LXNpemU6MTJweH0KLmYtZXJye2JvcmRlci1jb2xvcjp2YXIoLS1iYWQpIWltcG9ydGFudH0KCi8qID09PT09IOCmruCni+CmoeCmvuCmsiA9PT09PSAqLwoubW9kYWwtb3Z7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtiYWNrZ3JvdW5kOnJnYmEoMTAsMTAsMjUsLjUpO3otaW5kZXg6NzA7ZGlzcGxheTpub25lO2FsaWduLWl0ZW1zOmZsZXgtc3RhcnQ7anVzdGlmeS1jb250ZW50OmNlbnRlcjtwYWRkaW5nOjIwcHg7b3ZlcmZsb3cteTphdXRvfQoubW9kYWwtb3Yub257ZGlzcGxheTpmbGV4fQoubW9kYWx7YmFja2dyb3VuZDp2YXIoLS1zKTtib3JkZXItcmFkaXVzOjE2cHg7d2lkdGg6bWluKDY0MHB4LDEwMCUpO21hcmdpbjoyMHB4IDA7cGFkZGluZzoyMHB4fQoubW9kYWwtaGR7ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tYm90dG9tOjE0cHh9Ci5tb2RhbC1oZCBoM3tmb250LXNpemU6MTdweH0KLm1vZGFsLWNsb3Nle3dpZHRoOjMycHg7aGVpZ2h0OjMycHg7Ym9yZGVyLXJhZGl1czo4cHg7YmFja2dyb3VuZDp2YXIoLS1zMik7Ym9yZGVyOjB9Ci5tb2RhbC1mdHtkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7anVzdGlmeS1jb250ZW50OmZsZXgtZW5kO21hcmdpbi10b3A6MTZweDtmbGV4LXdyYXA6d3JhcH0KCi8qID09PT09IOCmquCmo+CnjeCmryDgpqvgprDgp43gpq4g4Kas4Ka/4Ka24KeH4Ka3ID09PT09ICovCi5pbWdwaWNre2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6MTBweH0KLmltZ3RpbGV7d2lkdGg6NzhweDtoZWlnaHQ6NzhweDtib3JkZXItcmFkaXVzOjEwcHg7YmFja2dyb3VuZDp2YXIoLS1zMikgY2VudGVyL2NvdmVyIG5vLXJlcGVhdDtwb3NpdGlvbjpyZWxhdGl2ZTtib3JkZXI6MXB4IGRhc2hlZCB2YXIoLS1sbil9Ci5pbWd0aWxlIGJ7cG9zaXRpb246YWJzb2x1dGU7dG9wOjJweDtyaWdodDoycHg7YmFja2dyb3VuZDp2YXIoLS1hYyk7Y29sb3I6I2ZmZjtmb250LXNpemU6OXB4O3BhZGRpbmc6MXB4IDVweDtib3JkZXItcmFkaXVzOjVweH0KLmltZ3RpbGUgYnV0dG9ue3Bvc2l0aW9uOmFic29sdXRlO2JvdHRvbToycHg7cmlnaHQ6MnB4O2JhY2tncm91bmQ6dmFyKC0tYmFkKTtjb2xvcjojZmZmO3dpZHRoOjIwcHg7aGVpZ2h0OjIwcHg7Ym9yZGVyLXJhZGl1czo2cHg7Zm9udC1zaXplOjExcHg7Ym9yZGVyOjB9Ci5pbWdhZGR7d2lkdGg6NzhweDtoZWlnaHQ6NzhweDtib3JkZXItcmFkaXVzOjEwcHg7Ym9yZGVyOjEuNXB4IGRhc2hlZCB2YXIoLS1sbik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToyMnB4O2NvbG9yOnZhcigtLW11KTtiYWNrZ3JvdW5kOnZhcigtLXMyKX0KLnZsaXN0e2Rpc3BsYXk6Z3JpZDtnYXA6OHB4fQoudnJvdzJ7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxLjRmciAuOWZyIC43ZnIgYXV0bztnYXA6OHB4O2FsaWduLWl0ZW1zOmNlbnRlcn0KQG1lZGlhKG1heC13aWR0aDo2MDBweCl7LnZyb3cye2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dyaWQtdGVtcGxhdGUtYXJlYXM6ImEgYiIgImMgZCJ9fQoKLyogPT09PT0g4Kab4KeL4KafIOCmnOCmv+CmqOCmv+CmuCA9PT09PSAqLwoudG9hc3R7cG9zaXRpb246Zml4ZWQ7bGVmdDo1MCU7Ym90dG9tOjI2cHg7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTUwJSk7YmFja2dyb3VuZDojMTExO2NvbG9yOiNmZmY7cGFkZGluZzoxMXB4IDIwcHg7Ym9yZGVyLXJhZGl1czoxMHB4O29wYWNpdHk6MDtwb2ludGVyLWV2ZW50czpub25lO3RyYW5zaXRpb246b3BhY2l0eSAuMnM7ei1pbmRleDo5MDtmb250LXNpemU6MTMuNXB4fQoudG9hc3Quc2hvd3tvcGFjaXR5OjF9Ci50b2FzdC5iYWR7YmFja2dyb3VuZDp2YXIoLS1iYWQpfQouc3Bpbnt3aWR0aDozMnB4O2hlaWdodDozMnB4O2JvcmRlcjozcHggc29saWQgdmFyKC0tbG4pO2JvcmRlci10b3AtY29sb3I6dmFyKC0tYWMpO2JvcmRlci1yYWRpdXM6NTAlO2FuaW1hdGlvbjpzcCAuOHMgbGluZWFyIGluZmluaXRlO21hcmdpbjozMHB4IGF1dG99CkBrZXlmcmFtZXMgc3B7dG97dHJhbnNmb3JtOnJvdGF0ZSgzNjBkZWcpfX0KLmVtcHR5e3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6NDBweCAxNnB4O2NvbG9yOnZhcigtLW11KX0KLnN3YXRjaHt3aWR0aDozNHB4O2hlaWdodDozNHB4O2JvcmRlci1yYWRpdXM6OXB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbG4pfQouY29sb3Jyb3d7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLnFyYm94e2JhY2tncm91bmQ6I2ZmZjtwYWRkaW5nOjE0cHg7Ym9yZGVyLXJhZGl1czoxMnB4O2Rpc3BsYXk6aW5saW5lLWJsb2NrfQouaGVscGJveHtiYWNrZ3JvdW5kOnZhcigtLWFjLWwpO2NvbG9yOnZhcigtLWFjKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4IDEzcHg7Zm9udC1zaXplOjEyLjVweDttYXJnaW4tYm90dG9tOjEycHh9Ci5tb25ve2ZvbnQtZmFtaWx5OnVpLW1vbm9zcGFjZSxNZW5sbyxDb25zb2xhcyxtb25vc3BhY2U7Zm9udC1zaXplOjEzcHg7YmFja2dyb3VuZDp2YXIoLS1zMik7cGFkZGluZzoycHggN3B4O2JvcmRlci1yYWRpdXM6NnB4fQouc2Vzcm93e2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7cGFkZGluZzoxMHB4IDA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbG4pO2dhcDoxMHB4fQouYXVkaXRyb3d7cGFkZGluZzo5cHggMDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1sbik7Zm9udC1zaXplOjEzcHg7ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2dhcDoxMHB4fQpAbWVkaWEocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjpyZWR1Y2Upeyp7YW5pbWF0aW9uOm5vbmUhaW1wb3J0YW50O3RyYW5zaXRpb246bm9uZSFpbXBvcnRhbnR9fQo=")
ADMIN_JS = _b64("J3VzZSBzdHJpY3QnOwpjb25zdCAkPShzLHIpPT4ocnx8ZG9jdW1lbnQpLnF1ZXJ5U2VsZWN0b3Iocyk7CmNvbnN0ICQkPShzLHIpPT5bLi4uKHJ8fGRvY3VtZW50KS5xdWVyeVNlbGVjdG9yQWxsKHMpXTsKY29uc3QgZXNjPXM9PlN0cmluZyhzPT1udWxsPycnOnMpLnJlcGxhY2UoL1smPD4iJ10vZyxjPT4oeycmJzonJmFtcDsnLCc8JzonJmx0OycsJz4nOicmZ3Q7JywnIic6JyZxdW90OycsIiciOicmIzM5Oyd9W2NdKSk7CmNvbnN0IG1vbmV5PW49Pifgp7MnK051bWJlcihufHwwKS50b0xvY2FsZVN0cmluZygnYm4tQkQnKTsKY29uc3QgZWw9KHRhZyxhdHRycywuLi5raWRzKT0+e2NvbnN0IG49ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCh0YWcpO2Zvcihjb25zdCBrIGluIGF0dHJzfHx7fSl7aWYoaz09PSdodG1sJyluLmlubmVySFRNTD1hdHRyc1trXTtlbHNlIGlmKGsuc3RhcnRzV2l0aCgnb24nKSluLmFkZEV2ZW50TGlzdGVuZXIoay5zbGljZSgyKSxhdHRyc1trXSk7ZWxzZSBpZihhdHRyc1trXSE9bnVsbCluLnNldEF0dHJpYnV0ZShrLGF0dHJzW2tdKTt9Zm9yKGNvbnN0IGsgb2Yga2lkcy5mbGF0KCkpaWYoayE9bnVsbCluLmFwcGVuZENoaWxkKHR5cGVvZiBrPT09J3N0cmluZyc/ZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUoayk6ayk7cmV0dXJuIG47fTsKZnVuY3Rpb24gdG9hc3QobXNnLGJhZCl7Y29uc3QgdD0kKCcjdG9hc3QnKTt0LmNsYXNzTmFtZT0ndG9hc3Qgc2hvdycrKGJhZD8nIGJhZCc6JycpO3QudGV4dENvbnRlbnQ9bXNnO2NsZWFyVGltZW91dCh0b2FzdC5fdCk7dG9hc3QuX3Q9c2V0VGltZW91dCgoKT0+dC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93JyksMjgwMCk7fQpmdW5jdGlvbiBmbXREYXRlKHRzKXtjb25zdCBkPW5ldyBEYXRlKHRzKjEwMDApO3JldHVybiBkLnRvTG9jYWxlRGF0ZVN0cmluZygnYm4tQkQnLHtkYXk6J251bWVyaWMnLG1vbnRoOidzaG9ydCcseWVhcjonbnVtZXJpYyd9KSsnICcrZC50b0xvY2FsZVRpbWVTdHJpbmcoJ2JuLUJEJyx7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0J30pO30KCmxldCBDU1JGPScnLCBNRT1udWxsOwphc3luYyBmdW5jdGlvbiBhcGkocGF0aCxvcHQpewogb3B0PW9wdHx8e307CiBjb25zdCBoPU9iamVjdC5hc3NpZ24oeydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sb3B0LmhlYWRlcnN8fHt9KTsKIGlmKG9wdC5tZXRob2QmJm9wdC5tZXRob2QhPT0nR0VUJyloWydYLUNTUkYnXT1DU1JGOwogY29uc3Qgcj1hd2FpdCBmZXRjaChwYXRoLE9iamVjdC5hc3NpZ24oe30sb3B0LHtoZWFkZXJzOmh9KSk7CiBpZihyLnN0YXR1cz09PTQwMSl7c2hvd0xvZ2luKCk7dGhyb3cgbmV3IEVycm9yKCfgprLgppfgpofgpqgg4KaV4Kaw4KeB4KaoJyk7fQogY29uc3QgY3R5cGU9ci5oZWFkZXJzLmdldCgnY29udGVudC10eXBlJyl8fCcnOwogaWYoY3R5cGUuaW5jbHVkZXMoJ2FwcGxpY2F0aW9uL2pzb24nKSl7CiAgY29uc3Qgaj1hd2FpdCByLmpzb24oKTsKICBpZighci5vayl0aHJvdyBuZXcgRXJyb3Ioai5lcnJvcnx8J+CmuOCmruCmuOCnjeCmr+CmviDgprngpq/gprzgp4fgppvgp4cnKTsKICByZXR1cm4gajsKIH0KIGlmKCFyLm9rKXRocm93IG5ldyBFcnJvcign4Ka44Kau4Ka44KeN4Kav4Ka+IOCmueCmr+CmvOCnh+Cmm+CnhycpOwogcmV0dXJuIHI7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgprLgppfgpofgpqgKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmNvbnN0IGJvZHk9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Jvb3QnKTsKZnVuY3Rpb24gc2hvd0xvZ2luKCl7CiBib2R5LmlubmVySFRNTD1gPGRpdiBjbGFzcz0ibG9naW53cmFwIj48ZGl2IGNsYXNzPSJsb2dpbmNhcmQiPgogIDxoMT7wn5SQIOCmheCnjeCmr+CmvuCmoeCmruCmv+CmqCDgprLgppfgpofgpqg8L2gxPjxwIGNsYXNzPSJzdWIiPuCmpuCni+CmleCmvuCmqCDgpqjgpr/gpq/gprzgpqjgp43gpqTgp43gprDgpqMg4Kaq4KeN4Kav4Ka+4Kao4KeH4KayPC9wPgogIDxkaXYgaWQ9ImxvZ2luTXNnIj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpofgpongppzgpr7gprDgpqjgp4fgpq48L3NwYW4+PGlucHV0IGlkPSJsZ191IiBhdXRvY29tcGxldGU9InVzZXJuYW1lIj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqrgpr7gprjgppPgpq/gprzgpr7gprDgp43gpqE8L3NwYW4+PGlucHV0IGlkPSJsZ19wIiB0eXBlPSJwYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJjdXJyZW50LXBhc3N3b3JkIj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJmIiBpZD0ibGdfY29kZV93cmFwIiBoaWRkZW4+PHNwYW4+4KeoLeCmp+CmvuCmqiDgpq/gpr7gpprgpr7gpocg4KaV4KeL4KahICjgp6wg4Ka44KaC4KaW4KeN4Kav4Ka+KTwvc3Bhbj48aW5wdXQgaWQ9ImxnX2NvZGUiIGlucHV0bW9kZT0ibnVtZXJpYyIgbWF4bGVuZ3RoPSI2Ij48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJidG4gYmxvY2siIGlkPSJsZ19nbyI+4Kaq4KeN4Kaw4Kas4KeH4Ka2IOCmleCmsOCngeCmqDwvYnV0dG9uPgogPC9kaXY+PC9kaXY+YDsKICQoJyNsZ19nbycpLm9uY2xpY2s9ZG9Mb2dpbjsKICQoJyNsZ19wJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZT0+e2lmKGUua2V5PT09J0VudGVyJylkb0xvZ2luKCk7fSk7CiAkKCcjbGdfY29kZV93cmFwJykmJiQoJyNsZ19jb2RlJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZT0+e2lmKGUua2V5PT09J0VudGVyJylkb0xvZ2luKCk7fSk7CiBzZXRUaW1lb3V0KCgpPT4kKCcjbGdfdScpLmZvY3VzKCksNTApOwp9CmFzeW5jIGZ1bmN0aW9uIGRvTG9naW4oKXsKIGNvbnN0IHU9JCgnI2xnX3UnKS52YWx1ZS50cmltKCksIHA9JCgnI2xnX3AnKS52YWx1ZSwgY29kZT0kKCcjbGdfY29kZScpPyQoJyNsZ19jb2RlJykudmFsdWUudHJpbSgpOicnOwogY29uc3QgbXNnPSQoJyNsb2dpbk1zZycpOyBtc2cuaW5uZXJIVE1MPScnOwogaWYoIXV8fCFwKXttc2cuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJlcnJiYW5uZXIiPuCmh+CmieCmnOCmvuCmsOCmqOCnh+CmriDgppMg4Kaq4Ka+4Ka44KaT4Kav4Ka84Ka+4Kaw4KeN4KahIOCmpuCmv+CmqDwvZGl2Pic7cmV0dXJuO30KICQoJyNsZ19nbycpLmRpc2FibGVkPXRydWU7JCgnI2xnX2dvJykudGV4dENvbnRlbnQ9J+Cmr+CmvuCmmuCmvuCmhyDgprngpprgp43gppvgp4figKYnOwogdHJ5ewogIGNvbnN0IHI9YXdhaXQgZmV0Y2goJy9hZG1pbi9hcGkvbG9naW4nLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sYm9keTpKU09OLnN0cmluZ2lmeSh7dXNlcm5hbWU6dSxwYXNzd29yZDpwLGNvZGV9KX0pOwogIGNvbnN0IGo9YXdhaXQgci5qc29uKCk7CiAgaWYoIXIub2spdGhyb3cgbmV3IEVycm9yKGouZXJyb3J8fCfgpq3gp4HgprInKTsKICBpZihqLm5lZWRfY29kZSl7JCgnI2xnX2NvZGVfd3JhcCcpLmhpZGRlbj1mYWxzZTskKCcjbGdfY29kZScpLmZvY3VzKCk7JCgnI2xnX2dvJykuZGlzYWJsZWQ9ZmFsc2U7JCgnI2xnX2dvJykudGV4dENvbnRlbnQ9J+CmquCnjeCmsOCmrOCnh+CmtiDgppXgprDgp4HgpqgnO21zZy5pbm5lckhUTUw9JzxkaXYgY2xhc3M9Im9rYmFubmVyIj7gpoXgpqXgp4fgpqjgpp/gpr/gppXgp4fgpp/gprAg4KaF4KeN4Kav4Ka+4Kaq4KeH4KawIOCnrCDgprjgpoLgppbgp43gpq/gpr7gprAg4KaV4KeL4KahIOCmpuCmv+CmqDwvZGl2Pic7cmV0dXJuO30KICBDU1JGPWouY3NyZjtNRT17dXNlcm5hbWU6ai51c2VybmFtZSx0b3RwX29uOmoudG90cF9vbn07CiAgYm9vdCgpOwogfWNhdGNoKGUpe21zZy5pbm5lckhUTUw9YDxkaXYgY2xhc3M9ImVycmJhbm5lciI+JHtlc2MoZS5tZXNzYWdlKX08L2Rpdj5gOyQoJyNsZ19nbycpLmRpc2FibGVkPWZhbHNlOyQoJyNsZ19nbycpLnRleHRDb250ZW50PSfgpqrgp43gprDgpqzgp4fgprYg4KaV4Kaw4KeB4KaoJzt9Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpoXgp43gpq/gpr7gpqog4KaV4Ka+4Kag4Ka+4Kau4KeLCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpjb25zdCBOQVY9WwogWydkYXNoYm9hcmQnLCfgpqHgp43gpq/gpr7gprbgpqzgp4vgprDgp43gpqEnLCc8cGF0aCBkPSJNMyAzaDh2OEgzek0xMyAzaDh2NWgtOHpNMTMgMTJoOHY5aC04ek0zIDE1aDh2NkgzeiIvPiddLAogWydvcmRlcnMnLCfgpoXgprDgp43gpqHgpr7gprAnLCc8Y2lyY2xlIGN4PSI5IiBjeT0iMjEiIHI9IjEuNSIvPjxjaXJjbGUgY3g9IjE5IiBjeT0iMjEiIHI9IjEuNSIvPjxwYXRoIGQ9Ik0yIDNoM2wyLjYgMTIuNmEyIDIgMCAwIDAgMiAxLjZoOC44YTIgMiAwIDAgMCAyLTEuNkwyMiA3SDYiLz4nXSwKIFsncHJvZHVjdHMnLCfgpqrgpqPgp43gpq8nLCc8cGF0aCBkPSJNMjAgNyAxMiAzIDQgN3YxMGw4IDQgOC00eiIvPjxwYXRoIGQ9Ik00IDdsOCA0IDgtNE0xMiAxMXYxMCIvPiddLAogWydjYXRlZ29yaWVzJywn4KaV4KeN4Kav4Ka+4Kaf4Ka+4KaX4Kaw4Ka/JywnPHJlY3QgeD0iMyIgeT0iMyIgd2lkdGg9IjciIGhlaWdodD0iNyIvPjxyZWN0IHg9IjE0IiB5PSIzIiB3aWR0aD0iNyIgaGVpZ2h0PSI3Ii8+PHJlY3QgeD0iMyIgeT0iMTQiIHdpZHRoPSI3IiBoZWlnaHQ9IjciLz48cmVjdCB4PSIxNCIgeT0iMTQiIHdpZHRoPSI3IiBoZWlnaHQ9IjciLz4nXSwKIFsnY291cG9ucycsJ+CmleCngeCmquCmqCcsJzxwYXRoIGQ9Ik0zIDEwYTIgMiAwIDAgMSAyLTJoMTRhMiAyIDAgMCAxIDIgMnYxYTIgMiAwIDAgMCAwIDJ2MWEyIDIgMCAwIDEtMiAySDVhMiAyIDAgMCAxLTItMnYtMWEyIDIgMCAwIDAgMC0yeiIvPjxwYXRoIGQ9Ik05IDh2OCIvPiddLAogWydiYW5uZXJzJywn4Kas4KeN4Kav4Ka+4Kao4Ka+4KawJywnPHJlY3QgeD0iMyIgeT0iNSIgd2lkdGg9IjE4IiBoZWlnaHQ9IjE0IiByeD0iMiIvPjxwYXRoIGQ9Im0zIDE1IDUtNSA0IDQgNS01IDQgNCIvPiddLAogWydzZXR0aW5ncycsJ+CmuOCnh+Cmn+Cmv+CmguCmuCcsJzxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjMiLz48cGF0aCBkPSJNMTkuNCAxNWExLjYgMS42IDAgMCAwIC4zIDEuOGwuMS4xYTIgMiAwIDEgMS0yLjggMi44bC0uMS0uMWExLjYgMS42IDAgMCAwLTEuOC0uMyAxLjYgMS42IDAgMCAwLTEgMS41VjIxYTIgMiAwIDEgMS00IDB2LS4yYTEuNiAxLjYgMCAwIDAtMS0xLjUgMS42IDEuNiAwIDAgMC0xLjguM2wtLjEuMWEyIDIgMCAxIDEtMi44LTIuOGwuMS0uMWExLjYgMS42IDAgMCAwIC4zLTEuOCAxLjYgMS42IDAgMCAwLTEuNS0xSDNhMiAyIDAgMSAxIDAtNGguMmExLjYgMS42IDAgMCAwIDEuNS0xIDEuNiAxLjYgMCAwIDAtLjMtMS44bC0uMS0uMWEyIDIgMCAxIDEgMi44LTIuOGwuMS4xYTEuNiAxLjYgMCAwIDAgMS44LjNIOWExLjYgMS42IDAgMCAwIDEtMS41VjNhMiAyIDAgMSAxIDQgMHYuMmExLjYgMS42IDAgMCAwIDEgMS41IDEuNiAxLjYgMCAwIDAgMS44LS4zbC4xLS4xYTIgMiAwIDEgMSAyLjggMi44bC0uMS4xYTEuNiAxLjYgMCAwIDAtLjMgMS44VjlhMS42IDEuNiAwIDAgMCAxLjUgMUgyMWEyIDIgMCAxIDEgMCA0aC0uMmExLjYgMS42IDAgMCAwLTEuNSAxeiIvPiddLAogWydzZWN1cml0eScsJ+CmqOCmv+CmsOCmvuCmquCmpOCnjeCmpOCmvicsJzxwYXRoIGQ9Ik0xMiAyIDQgNnY2YzAgNSAzLjQgOC43IDggMTAgNC42LTEuMyA4LTUgOC0xMFY2eiIvPiddLApdOwpsZXQgUEVORElORz0wOwpmdW5jdGlvbiBzaGVsbCgpewogYm9keS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9ImFwcCBvbiI+CiAgPGRpdiBjbGFzcz0ic2NyaW0iIGlkPSJzY3JpbSI+PC9kaXY+CiAgPGFzaWRlIGNsYXNzPSJzaWRlIiBpZD0ic2lkZSI+PGRpdiBjbGFzcz0ic2lkZS1oZCI+8J+PqiDgpqbgp4vgppXgpr7gpqgg4KaF4KeN4Kav4Ka+4Kah4Kau4Ka/4KaoPC9kaXY+CiAgIDxuYXYgaWQ9InNpZGVOYXYiPjwvbmF2PgogICA8ZGl2IGNsYXNzPSJzaWRlLWZ0Ij7gprLgppfgpofgpqg6IDxiPiR7ZXNjKE1FLnVzZXJuYW1lKX08L2I+PGJyPjxhIGhyZWY9IiMiIGlkPSJsb2dvdXRCdG4iIHN0eWxlPSJjb2xvcjojZmY5YTlhIj7gprLgppfgpobgpongpp88L2E+PC9kaXY+PC9hc2lkZT4KICA8ZGl2IGNsYXNzPSJtYWluIj4KICAgPGRpdiBjbGFzcz0idG9wYiI+PGJ1dHRvbiBjbGFzcz0iYnVyZ2VyIiBpZD0iYnVyZ2VyIj7imLA8L2J1dHRvbj48aDEgaWQ9InBhZ2VUaXRsZSI+4Kah4KeN4Kav4Ka+4Ka24Kas4KeL4Kaw4KeN4KahPC9oMT48L2Rpdj4KICAgPGRpdiBjbGFzcz0iY29udGVudCIgaWQ9ImNvbnRlbnQiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PgogIDwvZGl2PgogPC9kaXY+PGRpdiBjbGFzcz0idG9hc3QiIGlkPSJ0b2FzdCI+PC9kaXY+PGRpdiBjbGFzcz0ibW9kYWwtb3YiIGlkPSJtb2RhbE92Ij48L2Rpdj5gOwogJCgnI3NpZGVOYXYnKS5pbm5lckhUTUw9TkFWLm1hcCgoW2ssbCxpY10pPT5gPGEgaHJlZj0iIyR7a30iIGRhdGEtaz0iJHtrfSI+PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiPiR7aWN9PC9zdmc+JHtsfSR7az09PSdvcmRlcnMnPyc8c3BhbiBjbGFzcz0iYmFkZ2UyIiBpZD0icGVuZEJhZGdlIiBzdHlsZT0iZGlzcGxheTpub25lIj48L3NwYW4+JzonJ308L2E+YCkuam9pbignJyk7CiAkKCcjYnVyZ2VyJykub25jbGljaz0oKT0+eyQoJyNzaWRlJykuY2xhc3NMaXN0LmFkZCgnb24nKTskKCcjc2NyaW0nKS5jbGFzc0xpc3QuYWRkKCdvbicpO307CiAkKCcjc2NyaW0nKS5vbmNsaWNrPSgpPT57JCgnI3NpZGUnKS5jbGFzc0xpc3QucmVtb3ZlKCdvbicpOyQoJyNzY3JpbScpLmNsYXNzTGlzdC5yZW1vdmUoJ29uJyk7fTsKICQkKCcjc2lkZU5hdiBhJykuZm9yRWFjaChhPT5hLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywoKT0+eyQoJyNzaWRlJykuY2xhc3NMaXN0LnJlbW92ZSgnb24nKTskKCcjc2NyaW0nKS5jbGFzc0xpc3QucmVtb3ZlKCdvbicpO30pKTsKICQoJyNsb2dvdXRCdG4nKS5vbmNsaWNrPWFzeW5jIGU9PntlLnByZXZlbnREZWZhdWx0KCk7dHJ5e2F3YWl0IGFwaSgnL2FkbWluL2FwaS9sb2dvdXQnLHttZXRob2Q6J1BPU1QnfSk7fWNhdGNoKF8pe31sb2NhdGlvbi5yZWxvYWQoKTt9OwogcG9sbFBlbmRpbmcoKTsKIHNldEludGVydmFsKHBvbGxQZW5kaW5nLDIwMDAwKTsKfQphc3luYyBmdW5jdGlvbiBwb2xsUGVuZGluZygpewogdHJ5e2NvbnN0IGQ9YXdhaXQgYXBpKCcvYWRtaW4vYXBpL3BvbGwnKTtQRU5ESU5HPWQucGVuZGluZztjb25zdCBiPSQoJyNwZW5kQmFkZ2UnKTtpZihiKXtiLnN0eWxlLmRpc3BsYXk9UEVORElORz8nZmxleCc6J25vbmUnO2IudGV4dENvbnRlbnQ9UEVORElORz45OT8nOTkrJzpQRU5ESU5HO319Y2F0Y2goXyl7fQp9CmZ1bmN0aW9uIGNsb3NlTW9kYWwoKXskKCcjbW9kYWxPdicpLmNsYXNzTGlzdC5yZW1vdmUoJ29uJyk7JCgnI21vZGFsT3YnKS5pbm5lckhUTUw9Jyc7fQpmdW5jdGlvbiBvcGVuTW9kYWwodGl0bGUsYm9keUh0bWwsZm9vdEh0bWwpewogJCgnI21vZGFsT3YnKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9Im1vZGFsIj48ZGl2IGNsYXNzPSJtb2RhbC1oZCI+PGgzPiR7dGl0bGV9PC9oMz48YnV0dG9uIGNsYXNzPSJtb2RhbC1jbG9zZSIgaWQ9Im1DbG9zZSI+4pyVPC9idXR0b24+PC9kaXY+CiAgPGRpdiBpZD0ibW9kYWxCb2R5Ij4ke2JvZHlIdG1sfTwvZGl2PiR7Zm9vdEh0bWw/YDxkaXYgY2xhc3M9Im1vZGFsLWZ0Ij4ke2Zvb3RIdG1sfTwvZGl2PmA6Jyd9PC9kaXY+YDsKICQoJyNtb2RhbE92JykuY2xhc3NMaXN0LmFkZCgnb24nKTsKICQoJyNtQ2xvc2UnKS5vbmNsaWNrPWNsb3NlTW9kYWw7CiAkKCcjbW9kYWxPdicpLm9uY2xpY2s9ZT0+e2lmKGUudGFyZ2V0LmlkPT09J21vZGFsT3YnKWNsb3NlTW9kYWwoKTt9Owp9CmZ1bmN0aW9uIG1hcmtFcnIoc2VsLG1zZyl7Y29uc3Qgbj0kKHNlbCk7aWYoIW4pcmV0dXJuO24uY2xhc3NMaXN0LmFkZCgnZi1lcnInKTtsZXQgZT1uLnBhcmVudEVsZW1lbnQucXVlcnlTZWxlY3RvcignLmVycnRleHQnKTtpZighZSl7ZT1lbCgnZGl2Jyx7Y2xhc3M6J2VycnRleHQnfSk7bi5wYXJlbnRFbGVtZW50LmFwcGVuZENoaWxkKGUpO31lLnRleHRDb250ZW50PW1zZzt9CmZ1bmN0aW9uIGNsZWFyRXJycyhyb290Mil7KHJvb3QyfHxkb2N1bWVudCkucXVlcnlTZWxlY3RvckFsbCgnLmYtZXJyJykuZm9yRWFjaChuPT5uLmNsYXNzTGlzdC5yZW1vdmUoJ2YtZXJyJykpOyhyb290Mnx8ZG9jdW1lbnQpLnF1ZXJ5U2VsZWN0b3JBbGwoJy5lcnJ0ZXh0JykuZm9yRWFjaChuPT5uLnJlbW92ZSgpKTt9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4Kaw4Ka+4KaJ4Kaf4Ka+4KawICjgprngp43gpq/gpr7gprbgpq3gpr/gpqTgp43gpqTgpr/gppUpCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpjb25zdCBQQUdFUz17fTsKZnVuY3Rpb24gcm91dGUobmFtZSxmbil7UEFHRVNbbmFtZV09Zm47fQphc3luYyBmdW5jdGlvbiByZW5kZXJSb3V0ZSgpewogY29uc3QgaD0obG9jYXRpb24uaGFzaHx8JyNkYXNoYm9hcmQnKS5zbGljZSgxKTsKIGNvbnN0IFtuYW1lLGFyZ109aC5zcGxpdCgnLycpOwogY29uc3QgcGFnZT1QQUdFU1tuYW1lXT9uYW1lOidkYXNoYm9hcmQnOwogJCQoJyNzaWRlTmF2IGEnKS5mb3JFYWNoKGE9PmEuY2xhc3NMaXN0LnRvZ2dsZSgnb24nLGEuZGF0YXNldC5rPT09cGFnZSkpOwogJCgnI3BhZ2VUaXRsZScpLnRleHRDb250ZW50PU5BVi5maW5kKG49Pm5bMF09PT1wYWdlKT8uWzFdfHwnJzsKICQoJyNjb250ZW50JykuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJzcGluIj48L2Rpdj4nOwogdHJ5e2F3YWl0IFBBR0VTW3BhZ2VdKGFyZyk7fWNhdGNoKGUpeyQoJyNjb250ZW50JykuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJlbXB0eSI+8J+YlSAke2VzYyhlLm1lc3NhZ2UpfTwvZGl2PmA7fQp9CmFkZEV2ZW50TGlzdGVuZXIoJ2hhc2hjaGFuZ2UnLHJlbmRlclJvdXRlKTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpqHgp43gpq/gpr7gprbgpqzgp4vgprDgp43gpqEKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCnJvdXRlKCdkYXNoYm9hcmQnLGFzeW5jKCk9PnsKIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYWRtaW4vYXBpL2Rhc2hib2FyZCcpOwogY29uc3QgbWF4PU1hdGgubWF4KDEsLi4uZC5zZXJpZXMubWFwKHg9PngucmV2ZW51ZSkpOwogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YAogIDxkaXYgY2xhc3M9ImdyaWQgZzQiPgogICA8ZGl2IGNsYXNzPSJzdGF0Ij48ZGl2IGNsYXNzPSJsYmwiPuCmhuCmnOCmleCnh+CmsCDgpoXgprDgp43gpqHgpr7gprA8L2Rpdj48Yj4ke2QudG9kYXkub3JkZXJzfTwvYj48ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4Ij4ke21vbmV5KGQudG9kYXkucmV2ZW51ZSl9PC9kaXY+PC9kaXY+CiAgIDxkaXYgY2xhc3M9InN0YXQiPjxkaXYgY2xhc3M9ImxibCI+4KaP4KaHIOCmuOCmquCnjeCmpOCmvuCmueCnhzwvZGl2PjxiPiR7ZC53ZWVrLm9yZGVyc308L2I+PGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweCI+JHttb25leShkLndlZWsucmV2ZW51ZSl9PC9kaXY+PC9kaXY+CiAgIDxkaXYgY2xhc3M9InN0YXQiPjxkaXYgY2xhc3M9ImxibCI+4KaP4KaHIOCmruCmvuCmuOCnhzwvZGl2PjxiPiR7ZC5tb250aC5vcmRlcnN9PC9iPjxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPiR7bW9uZXkoZC5tb250aC5yZXZlbnVlKX08L2Rpdj48L2Rpdj4KICAgPGRpdiBjbGFzcz0ic3RhdCAke2QucGVuZGluZz8nd2Fybic6Jyd9Ij48ZGl2IGNsYXNzPSJsYmwiPuCmheCmquCnh+CmleCnjeCmt+CmruCmvuCmoyDgpoXgprDgp43gpqHgpr7gprA8L2Rpdj48Yj4ke2QucGVuZGluZ308L2I+PGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweCI+JHtkLnRvc2hpcH0g4Kaf4Ka/IOCmtuCmv+CmquCmruCnh+CmqOCnjeCmn+CnhzwvZGl2PjwvZGl2PgogIDwvZGl2PgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gppfgpqQg4Ken4KeqIOCmpuCmv+CmqOCnh+CmsCDgpqzgpr/gppXgp43gprDgpr88L2gzPjxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpmbGV4LWVuZDtnYXA6NHB4O2hlaWdodDoxMjBweDttYXJnaW4tdG9wOjE0cHgiPgogICAke2Quc2VyaWVzLm1hcChzPT5gPGRpdiBzdHlsZT0iZmxleDoxO2JhY2tncm91bmQ6dmFyKC0tYWMtbCk7Ym9yZGVyLXJhZGl1czo0cHggNHB4IDAgMDtoZWlnaHQ6JHtNYXRoLm1heCg0LHMucmV2ZW51ZSoxMDAvbWF4KX0lIiB0aXRsZT0iJHttb25leShzLnJldmVudWUpfSI+PC9kaXY+YCkuam9pbignJyl9CiAgPC9kaXY+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZ3JpZCBnMiIgc3R5bGU9Im1hcmdpbi10b3A6MTRweCI+CiAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gprjgpr7gpq7gp43gpqrgp43gprDgpqTgpr/gppUg4KaF4Kaw4KeN4Kah4Ka+4KawPC9oMz4ke2QucmVjZW50Lmxlbmd0aD9kLnJlY2VudC5tYXAobz0+YDxkaXYgY2xhc3M9InNlc3JvdyI+PGEgaHJlZj0iI29yZGVycy8ke28uaWR9Ij48Yj4ke2VzYyhvLmNvZGUpfTwvYj4g4oCUICR7ZXNjKG8ubmFtZSl9PC9hPjxzcGFuIGNsYXNzPSJ0YWcgJHtvLnN0YXR1c30iPiR7c3RhdHVzQm4oby5zdGF0dXMpfTwvc3Bhbj48L2Rpdj5gKS5qb2luKCcnKTonPHAgY2xhc3M9Im11dGVkIj7gpo/gppbgpqjgp4sg4KaF4Kaw4KeN4Kah4Ka+4KawIOCmueCmr+CmvOCmqOCmvzwvcD4nfTwvZGl2PgogICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Ka44KeN4Kaf4KaVIOCmleCmruCnhyDgpq/gpr7gpprgp43gppvgp4c8L2gzPiR7ZC5sb3cubGVuZ3RoP2QubG93Lm1hcChwPT5gPGRpdiBjbGFzcz0ic2Vzcm93Ij48YSBocmVmPSIjcHJvZHVjdHMiPiR7ZXNjKHAudGl0bGUpfTwvYT48YiBzdHlsZT0iY29sb3I6dmFyKC0tYmFkKSI+JHtwLnN0b2NrPDA/J+CmreCnh+CmsOCmv+Cmr+CmvOCnh+CmqOCnjeCmnyc6cC5zdG9jaysnIOCmrOCmvuCmleCmvyd9PC9iPjwvZGl2PmApLmpvaW4oJycpOic8cCBjbGFzcz0ibXV0ZWQiPuCmuOCmrCDgpqDgpr/gppUg4KaG4Kab4KeHPC9wPid9PC9kaXY+CiAgPC9kaXY+CiAgJHtkLnRvcC5sZW5ndGg/YDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpo8g4Kau4Ka+4Ka44KeH4KawIOCmrOCnh+CmuOCnjeCmnyDgprjgp4fgprLgpr7gprA8L2gzPiR7ZC50b3AubWFwKHQ9PmA8ZGl2IGNsYXNzPSJzZXNyb3ciPjxzcGFuPiR7ZXNjKHQudGl0bGUpfTwvc3Bhbj48Yj4ke3QucX0g4Kas4Ka/4KaV4KeN4Kaw4Ka/PC9iPjwvZGl2PmApLmpvaW4oJycpfTwvZGl2PmA6Jyd9YDsKfSk7CmZ1bmN0aW9uIHN0YXR1c0JuKHMpe3JldHVybiB7cGVuZGluZzon4KaF4Kaq4KeH4KaV4KeN4Ka34Kau4Ka+4KajJyxjb25maXJtZWQ6J+CmqOCmv+CmtuCnjeCmmuCmv+CmpCcscHJvY2Vzc2luZzon4Kaq4KeN4Kaw4Ka44KeN4Kak4KeB4KakIOCmueCmmuCnjeCmm+Cnhycsc2hpcHBlZDon4Kaq4Ka+4Kag4Ka+4Kao4KeLIOCmueCmr+CmvOCnh+Cmm+CnhycsZGVsaXZlcmVkOifgpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Ka54Kav4Ka84KeH4Kab4KeHJyxjYW5jZWxsZWQ6J+CmrOCmvuCmpOCmv+CmsicscmV0dXJuZWQ6J+Cmq+Cnh+CmsOCmpCd9W3NdfHxzO30KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpoXgprDgp43gpqHgpr7gprAg4Kak4Ka+4Kay4Ka/4KaV4Ka+CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpyb3V0ZSgnb3JkZXJzJyxhc3luYyBhcmc9PnsKIGlmKGFyZyl7cmV0dXJuIHJlbmRlck9yZGVyRGV0YWlsKGFyZyk7fQogY29uc3QgcXM9bmV3IFVSTFNlYXJjaFBhcmFtcyhsb2NhdGlvbi5zZWFyY2gpOwogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9InRvb2xiYXIiPgogIDxpbnB1dCBjbGFzcz0iZ3JvdyIgaWQ9Im9fcSIgcGxhY2Vob2xkZXI9IuCmleCni+CmoSwg4Kao4Ka+4KauIOCmrOCmviDgpqvgp4vgpqgg4Kam4Ka/4Kav4Ka84KeHIOCmluCngeCmgeCmnOCngeCmqCIgdmFsdWU9IiR7ZXNjKHFzLmdldCgncScpfHwnJyl9Ij4KICA8c2VsZWN0IGlkPSJvX3N0YXR1cyI+PG9wdGlvbiB2YWx1ZT0iIj7gprjgpqwg4KaF4Kas4Ka44KeN4Kal4Ka+PC9vcHRpb24+JHtPYmplY3Qua2V5cyhTVExBQkVMKS5tYXAocz0+YDxvcHRpb24gdmFsdWU9IiR7c30iICR7cXMuZ2V0KCdzdGF0dXMnKT09PXM/J3NlbGVjdGVkJzonJ30+JHtTVExBQkVMW3NdfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogIDxhIGNsYXNzPSJidG4gZ2hvc3Qgc20iIGlkPSJvX2V4cG9ydCIgaHJlZj0iIyI+Q1NWIOCmoeCmvuCmieCmqOCmsuCni+CmoTwvYT48L2Rpdj4KICA8ZGl2IGlkPSJvX2JvZHkiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PmA7CiAkKCcjb19xJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZT0+e2lmKGUua2V5PT09J0VudGVyJylsb2FkT3JkZXJzKDEpO30pOwogJCgnI29fc3RhdHVzJykub25jaGFuZ2U9KCk9PmxvYWRPcmRlcnMoMSk7CiAkKCcjb19leHBvcnQnKS5vbmNsaWNrPWU9PntlLnByZXZlbnREZWZhdWx0KCk7Y29uc3QgcD1uZXcgVVJMU2VhcmNoUGFyYW1zKHtxOiQoJyNvX3EnKS52YWx1ZSxzdGF0dXM6JCgnI29fc3RhdHVzJykudmFsdWV9KTtsb2NhdGlvbi5ocmVmPScvYWRtaW4vYXBpL29yZGVycy5jc3Y/JytwLnRvU3RyaW5nKCk7fTsKIGF3YWl0IGxvYWRPcmRlcnMocXMuZ2V0KCdwYWdlJyl8fDEpOwp9KTsKY29uc3QgU1RMQUJFTD17cGVuZGluZzon4KaF4Kaq4KeH4KaV4KeN4Ka34Kau4Ka+4KajJyxjb25maXJtZWQ6J+CmqOCmv+CmtuCnjeCmmuCmv+CmpCcscHJvY2Vzc2luZzon4Kaq4KeN4Kaw4Ka44KeN4Kak4KeB4KakIOCmueCmmuCnjeCmm+Cnhycsc2hpcHBlZDon4Kaq4Ka+4Kag4Ka+4Kao4KeLIOCmueCmr+CmvOCnh+Cmm+CnhycsZGVsaXZlcmVkOifgpqHgp4fgprLgpr/gpq3gpr7gprDgpr8g4Ka54Kav4Ka84KeH4Kab4KeHJyxjYW5jZWxsZWQ6J+CmrOCmvuCmpOCmv+CmsicscmV0dXJuZWQ6J+Cmq+Cnh+CmsOCmpCd9Owphc3luYyBmdW5jdGlvbiBsb2FkT3JkZXJzKHBhZ2UpewogY29uc3QgcD1uZXcgVVJMU2VhcmNoUGFyYW1zKHtxOiQoJyNvX3EnKS52YWx1ZSxzdGF0dXM6JCgnI29fc3RhdHVzJykudmFsdWUscGFnZX0pOwogY29uc3QgZD1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvb3JkZXJzPycrcC50b1N0cmluZygpKTsKICQoJyNvX2JvZHknKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9InRibHdyYXAiPjx0YWJsZT48dGhlYWQ+PHRyPjx0aD7gppXgp4vgpqE8L3RoPjx0aD7gpqTgpr7gprDgpr/gppY8L3RoPjx0aD7gppfgp43gprDgpr7gprngppU8L3RoPjx0aD7gppzgp4fgprLgpr48L3RoPjx0aD7gpq7gp4vgpp88L3RoPjx0aD7gpqrgp4fgpq7gp4fgpqjgp43gpp88L3RoPjx0aD7gpoXgpqzgprjgp43gpqXgpr48L3RoPjwvdHI+PC90aGVhZD4KICA8dGJvZHk+JHtkLml0ZW1zLm1hcChvPT5gPHRyIGNsYXNzPSJjbGsiIGRhdGEtaWQ9IiR7by5pZH0iIHN0eWxlPSJjdXJzb3I6cG9pbnRlciI+PHRkPjxiPiR7ZXNjKG8uY29kZSl9PC9iPjwvdGQ+PHRkPiR7Zm10RGF0ZShvLmNyZWF0ZWQpfTwvdGQ+PHRkPiR7ZXNjKG8ubmFtZSl9PGJyPjxzcGFuIGNsYXNzPSJtdXRlZCI+JHtlc2Moby5waG9uZSl9PC9zcGFuPjwvdGQ+PHRkPiR7ZXNjKG8uZGlzdHJpY3QpfTwvdGQ+PHRkPiR7bW9uZXkoby50b3RhbCl9PC90ZD4KICAgPHRkPiR7by5wYXltZW50PT09J2NvZCc/J0NPRCc6by5wYXltZW50LnRvVXBwZXJDYXNlKCl9PGJyPjxzcGFuIGNsYXNzPSJ0YWcgJHtvLnBheV9zdGF0dXN9Ij4ke28ucGF5X3N0YXR1cz09PSdwYWlkJz8n4Kaq4Kaw4Ka/4Ka24KeL4Kan4Ka/4KakJzon4KaF4Kaq4Kaw4Ka/4Ka24KeL4Kan4Ka/4KakJ308L3NwYW4+PC90ZD48dGQ+PHNwYW4gY2xhc3M9InRhZyAke28uc3RhdHVzfSI+JHtTVExBQkVMW28uc3RhdHVzXX08L3NwYW4+PC90ZD48L3RyPmApLmpvaW4oJycpfHwnPHRyPjx0ZCBjb2xzcGFuPSI3IiBjbGFzcz0iZW1wdHkiPuCmleCni+CmqOCniyDgpoXgprDgp43gpqHgpr7gprAg4Kao4KeH4KaHPC90ZD48L3RyPid9PC90Ym9keT48L3RhYmxlPjwvZGl2PgogICR7ZC5wYWdlcz4xP2A8ZGl2IGNsYXNzPSJwYWdlciI+JHtwYWdlckh0bWwoZC5wYWdlLGQucGFnZXMpfTwvZGl2PmA6Jyd9YDsKICQkKCcjb19ib2R5IHRyLmNsaycpLmZvckVhY2godHI9PnRyLm9uY2xpY2s9KCk9Pntsb2NhdGlvbi5oYXNoPSdvcmRlcnMvJyt0ci5kYXRhc2V0LmlkO30pOwogJCQoJyNvX2JvZHkgLnBhZ2VyIGJ1dHRvbicpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT5sb2FkT3JkZXJzKGIuZGF0YXNldC5wKSk7Cn0KZnVuY3Rpb24gcGFnZXJIdG1sKHBhZ2UscGFnZXMpe2xldCBvPVtdO2ZvcihsZXQgaT1NYXRoLm1heCgxLHBhZ2UtMik7aTw9TWF0aC5taW4ocGFnZXMscGFnZSsyKTtpKyspby5wdXNoKGA8YnV0dG9uIGRhdGEtcD0iJHtpfSIgY2xhc3M9IiR7aT09cGFnZT8nb24nOicnfSI+JHtpfTwvYnV0dG9uPmApO3JldHVybiBvLmpvaW4oJycpO30KCmFzeW5jIGZ1bmN0aW9uIHJlbmRlck9yZGVyRGV0YWlsKGlkKXsKIGNvbnN0IG89YXdhaXQgYXBpKCcvYWRtaW4vYXBpL29yZGVycy8nK2lkKTsKICQoJyNwYWdlVGl0bGUnKS50ZXh0Q29udGVudD0n4KaF4Kaw4KeN4Kah4Ka+4KawICcrby5jb2RlOwogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YDxhIGhyZWY9IiNvcmRlcnMiIGNsYXNzPSJtdXRlZCI+4oC5IOCmheCmsOCnjeCmoeCmvuCmsCDgpqTgpr7gprLgpr/gppXgpr7gpq/gprwg4Kar4Ka/4Kaw4KeB4KaoPC9hPgogIDxkaXYgY2xhc3M9ImdyaWQgZzIiIHN0eWxlPSJtYXJnaW4tdG9wOjEycHg7YWxpZ24taXRlbXM6c3RhcnQiPgogICA8ZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+PGgzPuCmquCmo+CnjeCmr+CmuOCmruCnguCmuTwvaDM+PGRpdiBjbGFzcz0idGJsd3JhcCI+PHRhYmxlPjx0aGVhZD48dHI+PHRoPuCmquCmo+CnjeCmrzwvdGg+PHRoPuCmpuCmvuCmrjwvdGg+PHRoPuCmquCmsOCmv+CmruCmvuCmozwvdGg+PHRoPuCmr+Cni+Cml+Cmq+CmsjwvdGg+PC90cj48L3RoZWFkPgogICAgIDx0Ym9keT4ke28uaXRlbXMubWFwKGk9PmA8dHI+PHRkPiR7ZXNjKGkudGl0bGUpfSR7aS52YXJpYW50P2A8YnI+PHNwYW4gY2xhc3M9Im11dGVkIj4ke2VzYyhpLnZhcmlhbnQpfTwvc3Bhbj5gOicnfTwvdGQ+PHRkPiR7bW9uZXkoaS5wcmljZSl9PC90ZD48dGQ+JHtpLnF0eX08L3RkPjx0ZD4ke21vbmV5KGkucHJpY2UqaS5xdHkpfTwvdGQ+PC90cj5gKS5qb2luKCcnKX08L3Rib2R5PjwvdGFibGU+PC9kaXY+CiAgICAgPGRpdiBzdHlsZT0idGV4dC1hbGlnbjpsZWZ0O21hcmdpbi10b3A6MTBweDtmb250LXNpemU6MTMuNXB4Ij4KICAgICAgPGRpdiBjbGFzcz0ic2Vzcm93Ij48c3Bhbj7gprjgpr7gpqzgpp/gp4vgpp/gpr7gprI8L3NwYW4+PGI+JHttb25leShvLnN1YnRvdGFsKX08L2I+PC9kaXY+CiAgICAgICR7by5kaXNjb3VudD9gPGRpdiBjbGFzcz0ic2Vzcm93Ij48c3Bhbj7gppvgpr7gpqHgprwgJHtvLmNvdXBvbj8nKCcrZXNjKG8uY291cG9uKSsnKSc6Jyd9PC9zcGFuPjxiPuKIkiR7bW9uZXkoby5kaXNjb3VudCl9PC9iPjwvZGl2PmA6Jyd9CiAgICAgIDxkaXYgY2xhc3M9InNlc3JvdyI+PHNwYW4+4Kah4KeH4Kay4Ka/4Kat4Ka+4Kaw4Ka/IOCmmuCmvuCmsOCnjeCmnDwvc3Bhbj48Yj4ke21vbmV5KG8uc2hpcHBpbmcpfTwvYj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic2Vzcm93IiBzdHlsZT0iZm9udC1zaXplOjE2cHgiPjxzcGFuPuCmuOCmsOCnjeCmrOCmruCni+Cmnzwvc3Bhbj48Yj4ke21vbmV5KG8udG90YWwpfTwvYj48L2Rpdj48L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gppfgp43gprDgpr7gprngppUg4KaTIOCmoOCmv+CmleCmvuCmqOCmvjwvaDM+PHA+PGI+JHtlc2Moby5uYW1lKX08L2I+IOKAlCAke2VzYyhvLnBob25lKX0ke28ucHJldl9vcmRlcnM/YCA8c3BhbiBjbGFzcz0ibXV0ZWQiPijgpobgppfgp4cgJHtvLnByZXZfb3JkZXJzfeCmn+CmvyDgpoXgprDgp43gpqHgpr7gprApPC9zcGFuPmA6JyA8c3BhbiBjbGFzcz0ibXV0ZWQiPijgpqjgpqTgp4Hgpqgg4KaX4KeN4Kaw4Ka+4Ka54KaVKTwvc3Bhbj4nfTwvcD4KICAgICA8cD4ke2VzYyhvLmRpc3RyaWN0KX0g4oCUICR7ZXNjKG8uYWRkcmVzcyl9PC9wPiR7by5ub3RlP2A8cCBjbGFzcz0ibXV0ZWQiPuCmqOCni+CmnzogJHtlc2Moby5ub3RlKX08L3A+YDonJ308L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqrgp4fgpq7gp4fgpqjgp43gpp88L2gzPjxwPiR7by5wYXltZW50PT09J2NvZCc/J+CmleCnjeCmr+CmvuCmtiDgpoXgpqgg4Kah4KeH4Kay4Ka/4Kat4Ka+4Kaw4Ka/JzpvLnBheW1lbnQudG9VcHBlckNhc2UoKX0g4oCUIDxzcGFuIGNsYXNzPSJ0YWcgJHtvLnBheV9zdGF0dXN9Ij4ke28ucGF5X3N0YXR1cz09PSdwYWlkJz8n4Kaq4Kaw4Ka/4Ka24KeL4Kan4Ka/4KakJzon4KaF4Kaq4Kaw4Ka/4Ka24KeL4Kan4Ka/4KakJ308L3NwYW4+PC9wPgogICAgICR7by5wYXlfcmVmP2A8cD5UcnhJRDogPHNwYW4gY2xhc3M9Im1vbm8iPiR7ZXNjKG8ucGF5X3JlZil9PC9zcGFuPiDigJQg4Kaq4KeN4Kaw4KeH4Kaw4KaVOiAke2VzYyhvLnBheV9zZW5kZXIpfTwvcD5gOicnfQogICAgICR7by5wYXltZW50IT09J2NvZCc/YDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCBzbSIgaWQ9InRvZ2dsZVBheSI+JHtvLnBheV9zdGF0dXM9PT0ncGFpZCc/J+CmheCmquCmsOCmv+CmtuCni+Cmp+Cmv+CmpCDgppXgprDgp4HgpqgnOifgpqrgprDgpr/gprbgp4vgpqfgpr/gpqQg4Kaa4Ka/4Ka54KeN4Kao4Ka/4KakIOCmleCmsOCngeCmqCd9PC9idXR0b24+YDonJ308L2Rpdj4KICAgPC9kaXY+CiAgIDxkaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4KaF4Kas4Ka44KeN4Kal4Ka+IOCmquCmsOCmv+CmrOCmsOCnjeCmpOCmqDwvaDM+PHNwYW4gY2xhc3M9InRhZyAke28uc3RhdHVzfSIgc3R5bGU9ImZvbnQtc2l6ZToxM3B4Ij4ke1NUTEFCRUxbby5zdGF0dXNdfTwvc3Bhbj4KICAgICAke28ubmV4dC5sZW5ndGg/YDxkaXYgY2xhc3M9ImYiIHN0eWxlPSJtYXJnaW4tdG9wOjEycHgiPjxzcGFuPuCmqOCmpOCngeCmqCDgpoXgpqzgprjgp43gpqXgpr48L3NwYW4+PHNlbGVjdCBpZD0ic3RTZWwiPiR7by5uZXh0Lm1hcChzPT5gPG9wdGlvbiB2YWx1ZT0iJHtzfSI+JHtTVExBQkVMW3NdfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqjgp4vgpp8gKOCmkOCmmuCnjeCmm+Cmv+CmlSk8L3NwYW4+PGlucHV0IGlkPSJzdE5vdGUiIG1heGxlbmd0aD0iMzAwIj48L2Rpdj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJsb2NrIiBpZD0ic3RHbyI+4KaG4Kaq4Kah4KeH4KafIOCmleCmsOCngeCmqDwvYnV0dG9uPmA6JzxwIGNsYXNzPSJtdXRlZCIgc3R5bGU9Im1hcmdpbi10b3A6MTBweCI+4KaP4KaHIOCmheCmsOCnjeCmoeCmvuCmsOCnhyDgpobgprAg4Kaq4Kaw4Ka/4Kas4Kaw4KeN4Kak4KaoIOCmleCmsOCmviDgpq/gpr7gpqzgp4cg4Kao4Ka+PC9wPid9PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4KaH4Kak4Ka/4Ka54Ka+4Ka4PC9oMz4ke28uZXZlbnRzLm1hcChlPT5gPGRpdiBjbGFzcz0ic2Vzcm93Ij48c3Bhbj4ke1NUTEFCRUxbZS5zdGF0dXNdfHxlLnN0YXR1c30ke2Uubm90ZT8nIOKAlCAnK2VzYyhlLm5vdGUpOicnfTwvc3Bhbj48c3BhbiBjbGFzcz0ibXV0ZWQiPiR7Zm10RGF0ZShlLmNyZWF0ZWQpfTwvc3Bhbj48L2Rpdj5gKS5qb2luKCcnKX08L2Rpdj4KICAgPC9kaXY+PC9kaXY+YDsKIGlmKCQoJyNzdEdvJykpJCgnI3N0R28nKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBiPSQoJyNzdEdvJyk7Yi5kaXNhYmxlZD10cnVlO2IudGV4dENvbnRlbnQ9J+CmueCmmuCnjeCmm+Cnh+KApic7CiAgdHJ5e2F3YWl0IGFwaSgnL2FkbWluL2FwaS9vcmRlcnMvJytvLmlkKycvc3RhdHVzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtzdGF0dXM6JCgnI3N0U2VsJykudmFsdWUsbm90ZTokKCcjc3ROb3RlJykudmFsdWV9KX0pO3RvYXN0KCfgpoXgpqzgprjgp43gpqXgpr4g4KaG4Kaq4Kah4KeH4KafIOCmueCmr+CmvOCnh+Cmm+CnhycpO3JlbmRlck9yZGVyRGV0YWlsKGlkKTtwb2xsUGVuZGluZygpO30KICBjYXRjaChlKXt0b2FzdChlLm1lc3NhZ2UsdHJ1ZSk7Yi5kaXNhYmxlZD1mYWxzZTtiLnRleHRDb250ZW50PSfgpobgpqrgpqHgp4fgpp8g4KaV4Kaw4KeB4KaoJzt9CiB9OwogaWYoJCgnI3RvZ2dsZVBheScpKSQoJyN0b2dnbGVQYXknKS5vbmNsaWNrPWFzeW5jKCk9PnsKICB0cnl7YXdhaXQgYXBpKCcvYWRtaW4vYXBpL29yZGVycy8nK28uaWQrJy9wYXknLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe3BheV9zdGF0dXM6by5wYXlfc3RhdHVzPT09J3BhaWQnPyd1bnBhaWQnOidwYWlkJ30pfSk7dG9hc3QoJ+CmquCnh+CmruCnh+CmqOCnjeCmnyDgpoXgpqzgprjgp43gpqXgpr4g4KaG4Kaq4Kah4KeH4KafIOCmueCmr+CmvOCnh+Cmm+CnhycpO3JlbmRlck9yZGVyRGV0YWlsKGlkKTt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KIH07Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpqrgpqPgp43gpq8KICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCnJvdXRlKCdwcm9kdWN0cycsYXN5bmMoKT0+ewogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9InRvb2xiYXIiPjxpbnB1dCBjbGFzcz0iZ3JvdyIgaWQ9InBfcSIgcGxhY2Vob2xkZXI9IuCmquCmo+CnjeCmr+Cnh+CmsCDgpqjgpr7gpq4g4Kam4Ka/4Kav4Ka84KeHIOCmluCngeCmgeCmnOCngeCmqCI+PGJ1dHRvbiBjbGFzcz0iY2hpcCIgaWQ9InBfbG93Ij7imqDvuI8g4KaV4KauIOCmuOCnjeCmn+CmlTwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InBfYWRkIiBzdHlsZT0ibWFyZ2luLXJpZ2h0OmF1dG8iPisg4Kao4Kak4KeB4KaoIOCmquCmo+CnjeCmrzwvYnV0dG9uPjwvZGl2PgogIDxkaXYgaWQ9InBfYm9keSI+PGRpdiBjbGFzcz0ic3BpbiI+PC9kaXY+PC9kaXY+YDsKIGxldCBsb3c9ZmFsc2U7CiAkKCcjcF9xJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZT0+e2lmKGUua2V5PT09J0VudGVyJylsb2FkUHJvZHVjdHMoMSxsb3cpO30pOwogJCgnI3BfbG93Jykub25jbGljaz0oKT0+e2xvdz0hbG93OyQoJyNwX2xvdycpLmNsYXNzTGlzdC50b2dnbGUoJ29uJyxsb3cpO2xvYWRQcm9kdWN0cygxLGxvdyk7fTsKICQoJyNwX2FkZCcpLm9uY2xpY2s9KCk9PnByb2R1Y3RNb2RhbCgpOwogYXdhaXQgbG9hZFByb2R1Y3RzKDEsZmFsc2UpOwp9KTsKYXN5bmMgZnVuY3Rpb24gbG9hZFByb2R1Y3RzKHBhZ2UsbG93KXsKIGNvbnN0IHA9bmV3IFVSTFNlYXJjaFBhcmFtcyh7cTokKCcjcF9xJykudmFsdWUscGFnZSxsb3c6bG93PycxJzonJ30pOwogY29uc3QgZD1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvcHJvZHVjdHM/JytwLnRvU3RyaW5nKCkpOwogJCgnI3BfYm9keScpLmlubmVySFRNTD1gPGRpdiBjbGFzcz0idGJsd3JhcCI+PHRhYmxlPjx0aGVhZD48dHI+PHRoPuCmquCmo+CnjeCmrzwvdGg+PHRoPuCmpuCmvuCmrjwvdGg+PHRoPuCmuOCnjeCmn+CmlTwvdGg+PHRoPuCmrOCmv+CmleCnjeCmsOCmvzwvdGg+PHRoPuCmheCmrOCmuOCnjeCmpeCmvjwvdGg+PHRoPjwvdGg+PC90cj48L3RoZWFkPgogIDx0Ym9keT4ke2QuaXRlbXMubWFwKHg9PmA8dHI+PHRkIHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo5cHgiPiR7eC5pbWc/YDxpbWcgc3JjPSIvdXBsb2Fkcy8ke2VzYyh4LmltZyl9IiBzdHlsZT0id2lkdGg6MzhweDtoZWlnaHQ6MzhweDtib3JkZXItcmFkaXVzOjhweDtvYmplY3QtZml0OmNvdmVyIj5gOmA8c3BhbiBzdHlsZT0id2lkdGg6MzhweDtoZWlnaHQ6MzhweDtib3JkZXItcmFkaXVzOjhweDtiYWNrZ3JvdW5kOnZhcigtLXMyKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXIiPiR7eC5pY29ufTwvc3Bhbj5gfTxzcGFuPiR7ZXNjKHgudGl0bGUpfTwvc3Bhbj48L3RkPgogICA8dGQ+JHttb25leSh4LmZpbmFsKX0ke3guc2FsZT9gPGJyPjxzIGNsYXNzPSJtdXRlZCI+JHttb25leSh4LnByaWNlKX08L3M+YDonJ308L3RkPjx0ZD4ke3guaGFzX3ZhcmlhbnRzPyfgpq3gp4fgprDgpr/gpq/gprzgp4fgpqjgp43gpp8nOih4LnN0b2NrPD01P2A8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tYmFkKSI+JHt4LnN0b2NrfTwvc3Bhbj5gOnguc3RvY2spfTwvdGQ+PHRkPiR7eC5zb2xkfTwvdGQ+CiAgIDx0ZD4ke3guYWN0aXZlPyc8c3BhbiBjbGFzcz0idGFnIGRlbGl2ZXJlZCI+4Ka44KaV4KeN4Kaw4Ka/4Kav4Ka8PC9zcGFuPic6JzxzcGFuIGNsYXNzPSJ0YWcgY2FuY2VsbGVkIj7gpqjgpr/gprfgp43gppXgp43gprDgpr/gpq/gprw8L3NwYW4+J30ke3guZmVhdHVyZWQ/JyA8c3BhbiBjbGFzcz0idGFnIGNvbmZpcm1lZCI+4Kar4Ka/4Kaa4Ka+4Kaw4KeN4KahPC9zcGFuPic6Jyd9PC90ZD4KICAgPHRkIHN0eWxlPSJ3aGl0ZS1zcGFjZTpub3dyYXAiPjxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCBzbSIgZGF0YS1lPSIke3guaWR9Ij7gprjgpq7gp43gpqrgpr7gpqbgpqjgpr48L2J1dHRvbj4gPGJ1dHRvbiBjbGFzcz0iYnRuIGRhbmdlciBzbSIgZGF0YS1kPSIke3guaWR9Ij7gpq7gp4Hgppvgp4Hgpqg8L2J1dHRvbj48L3RkPjwvdHI+YCkuam9pbignJyl8fCc8dHI+PHRkIGNvbHNwYW49IjYiIGNsYXNzPSJlbXB0eSI+4KaV4KeL4Kao4KeLIOCmquCmo+CnjeCmryDgpqrgpr7gppPgpq/gprzgpr4g4Kav4Ka+4Kav4Ka84Kao4Ka/PC90ZD48L3RyPid9PC90Ym9keT48L3RhYmxlPjwvZGl2PgogICR7ZC5wYWdlcz4xP2A8ZGl2IGNsYXNzPSJwYWdlciI+JHtwYWdlckh0bWwoZC5wYWdlLGQucGFnZXMpfTwvZGl2PmA6Jyd9YDsKICQkKCcjcF9ib2R5IFtkYXRhLWVdJykuZm9yRWFjaChiPT5iLm9uY2xpY2s9KCk9PnByb2R1Y3RNb2RhbChiLmRhdGFzZXQuZSkpOwogJCQoJyNwX2JvZHkgW2RhdGEtZF0nKS5mb3JFYWNoKGI9PmIub25jbGljaz0oKT0+ZGVsUHJvZHVjdChiLmRhdGFzZXQuZCxwYWdlLGxvdykpOwogJCQoJyNwX2JvZHkgLnBhZ2VyIGJ1dHRvbicpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT5sb2FkUHJvZHVjdHMoYi5kYXRhc2V0LnAsbG93KSk7Cn0KYXN5bmMgZnVuY3Rpb24gZGVsUHJvZHVjdChpZCxwYWdlLGxvdyl7CiBpZighY29uZmlybSgn4Kaq4Kaj4KeN4Kav4Kaf4Ka/IOCmruCngeCmm+CnhyDgpqvgp4fgprLgpqTgp4cg4Kaa4Ka+4KaoPycpKXJldHVybjsKIHRyeXtjb25zdCByPWF3YWl0IGFwaSgnL2FkbWluL2FwaS9wcm9kdWN0cy8nK2lkLHttZXRob2Q6J0RFTEVURSd9KTt0b2FzdChyLmhpZGRlbj8n4KaF4Kaw4KeN4Kah4Ka+4Kaw4KeHIOCmpeCmvuCmleCmvuCmr+CmvCDgpqrgpqPgp43gpq/gpp/gpr8g4Kay4KeB4KaV4Ka+4Kao4KeLIOCmueCmsuCniyc6J+CmquCmo+CnjeCmryDgpq7gp4Hgppvgp4cg4Kar4KeH4Kay4Ka+IOCmueCmr+CmvOCnh+Cmm+CnhycpO2xvYWRQcm9kdWN0cyhwYWdlLGxvdyk7fQogY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KfQphc3luYyBmdW5jdGlvbiBwcm9kdWN0TW9kYWwoaWQpewogY29uc3QgY2F0cz1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvY2F0ZWdvcmllcycpOwogbGV0IHA9e3RpdGxlOicnLGNhdGVnb3J5X2lkOicnLHByaWNlOicnLHNhbGVfcHJpY2U6Jycsc3RvY2s6MCxkZXNjcmlwdGlvbjonJyxzcGVjczonJyxpbWFnZXM6W10sdmFyaWFudHM6W10sZmVhdHVyZWQ6ZmFsc2UsYWN0aXZlOnRydWV9OwogaWYoaWQpcD1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvcHJvZHVjdHMvJytpZCk7CiBvcGVuTW9kYWwoaWQ/J+CmquCmo+CnjeCmryDgprjgpq7gp43gpqrgpr7gpqbgpqjgpr4nOifgpqjgpqTgp4Hgpqgg4Kaq4Kaj4KeN4KavJywgYAogIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmquCmo+CnjeCmr+Cnh+CmsCDgpqjgpr7gpq4gKjwvc3Bhbj48aW5wdXQgaWQ9InBmX3RpdGxlIiB2YWx1ZT0iJHtlc2MocC50aXRsZSl9IiBtYXhsZW5ndGg9IjIwMCI+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZjIiPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmleCnjeCmr+CmvuCmn+CmvuCml+CmsOCmvzwvc3Bhbj48c2VsZWN0IGlkPSJwZl9jYXQiPjxvcHRpb24gdmFsdWU9IiI+4oCUIOCmqOCnh+CmhyDigJQ8L29wdGlvbj4ke2NhdHMuaXRlbXMubWFwKGM9PmA8b3B0aW9uIHZhbHVlPSIke2MuaWR9IiAke3AuY2F0ZWdvcnlfaWQ9PWMuaWQ/J3NlbGVjdGVkJzonJ30+JHtlc2MoYy5pY29uKX0gJHtlc2MoYy5uYW1lKX08L29wdGlvbj5gKS5qb2luKCcnKX08L3NlbGVjdD48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiBjaGsiIHN0eWxlPSJhbGlnbi1zZWxmOmVuZCI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0icGZfZmVhdCIgJHtwLmZlYXR1cmVkPydjaGVja2VkJzonJ30+PHNwYW4+4Kar4Ka/4Kaa4Ka+4Kaw4KeN4KahIOCmquCmo+CnjeCmrzwvc3Bhbj48L2Rpdj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJmMiI+PGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kam4Ka+4KauICjgp7MpICo8L3NwYW4+PGlucHV0IGlkPSJwZl9wcmljZSIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtwLnByaWNlfHwnJ30iPjwvZGl2PgogICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpoXgpqvgpr7gprAg4Kam4Ka+4KauICjgppDgpprgp43gppvgpr/gppUpPC9zcGFuPjxpbnB1dCBpZD0icGZfc2FsZSIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtwLnNhbGVfcHJpY2V8fCcnfSI+PC9kaXY+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZiIgaWQ9InBmX3N0b2Nrd3JhcCI+PHNwYW4+4Ka44KeN4Kaf4KaVICjgpq3gp4fgprDgpr/gpq/gprzgp4fgpqjgp43gpp8g4Kao4Ka+IOCmpeCmvuCmleCmsuCnhyk8L3NwYW4+PGlucHV0IGlkPSJwZl9zdG9jayIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtwLnN0b2NrfHwwfSI+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kab4Kas4Ka/ICjgprjgprDgp43gpqzgp4vgpprgp43gppog4Keu4Kaf4Ka/IOKAlCDgpqrgp43gprDgpqXgpq7gpp/gpr8g4Kaq4KeN4Kaw4Kaa4KeN4Kab4KamIOCmueCmrOCnhyk8L3NwYW4+PGRpdiBjbGFzcz0iaW1ncGljayIgaWQ9InBmX2ltZ3MiPjwvZGl2PjxpbnB1dCB0eXBlPSJmaWxlIiBpZD0icGZfZmlsZSIgYWNjZXB0PSJpbWFnZS8qIiBoaWRkZW4+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kat4KeH4Kaw4Ka/4Kav4Ka84KeH4Kao4KeN4KafICjgprDgpoIv4Ka44Ka+4KaH4KacIOCmh+CmpOCnjeCmr+CmvuCmpuCmvyDigJQg4KaQ4Kaa4KeN4Kab4Ka/4KaVKTwvc3Bhbj48ZGl2IGNsYXNzPSJ2bGlzdCIgaWQ9InBmX3ZhcnMiPjwvZGl2PjxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIGdob3N0IHNtIiBpZD0icGZfdmFkZCIgc3R5bGU9Im1hcmdpbi10b3A6OHB4Ij4rIOCmreCnh+CmsOCmv+Cmr+CmvOCnh+CmqOCnjeCmnyDgpq/gp4vgppcg4KaV4Kaw4KeB4KaoPC9idXR0b24+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kas4Ka/4Kas4Kaw4KajPC9zcGFuPjx0ZXh0YXJlYSBpZD0icGZfZGVzYyIgbWF4bGVuZ3RoPSI2MDAwIj4ke2VzYyhwLmRlc2NyaXB0aW9uKX08L3RleHRhcmVhPjwvZGl2PgogIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmrOCniOCmtuCmv+Cmt+CnjeCmn+CnjeCmryAo4Kaq4KeN4Kaw4Kak4Ka/IOCmsuCmvuCmh+CmqOCnhyAi4Kao4Ka+4KauOiDgpq7gpr7gpqgiKTwvc3Bhbj48dGV4dGFyZWEgaWQ9InBmX3NwZWNzIiBwbGFjZWhvbGRlcj0i4Kas4KeN4Kaw4KeN4Kav4Ka+4Kao4KeN4KahOiDgpongpqbgpr7gprngprDgpqMmIzEwO+Cmk+CmnOCmqDog4Ker4Kem4KemIOCml+CnjeCmsOCmvuCmriIgbWF4bGVuZ3RoPSIzMDAwIj4ke2VzYyhwLnNwZWNzKX08L3RleHRhcmVhPjwvZGl2PgogIDxkaXYgY2xhc3M9ImYgY2hrIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJwZl9hY3RpdmUiICR7cC5hY3RpdmUhPT1mYWxzZT8nY2hlY2tlZCc6Jyd9PjxzcGFuPuCmquCmo+CnjeCmr+Cmn+CmvyDgpqbgp4vgppXgpr7gpqjgp4cg4Kam4KeH4KaW4Ka+4Kao4KeLIOCmueCmrOCnhzwvc3Bhbj48L2Rpdj5gLAogIGA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJtQ2FuY2VsIj7gpqzgpr7gpqTgpr/gprI8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJtU2F2ZSI+4Ka44KaC4Kaw4KaV4KeN4Ka34KajIOCmleCmsOCngeCmqDwvYnV0dG9uPmApOwogbGV0IGltYWdlcz1bLi4ucC5pbWFnZXNdLCB2YXJpYW50cz0ocC52YXJpYW50c3x8W10pLm1hcCh2PT4oe2xhYmVsOnYubGFiZWwscHJpY2U6di5wcmljZXx8Jycsc3RvY2s6di5zdG9ja30pKTsKIGZ1bmN0aW9uIHJlbmRlckltZ3MoKXsKICAkKCcjcGZfaW1ncycpLmlubmVySFRNTD1pbWFnZXMubWFwKChmLGkpPT5gPGRpdiBjbGFzcz0iaW1ndGlsZSIgc3R5bGU9ImJhY2tncm91bmQtaW1hZ2U6dXJsKCcvdXBsb2Fkcy8ke2VzYyhmKX0nKSI+JHtpPT09MD8nPGI+4Kaq4KeN4Kaw4Kaa4KeN4Kab4KamPC9iPic6Jyd9PGJ1dHRvbiBkYXRhLWk9IiR7aX0iPuKclTwvYnV0dG9uPjwvZGl2PmApLmpvaW4oJycpKyhpbWFnZXMubGVuZ3RoPDg/JzxkaXYgY2xhc3M9ImltZ2FkZCIgaWQ9InBmX2FkZGltZyI+KzwvZGl2Pic6JycpOwogICQkKCcjcGZfaW1ncyBbZGF0YS1pXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT57aW1hZ2VzLnNwbGljZSgrYi5kYXRhc2V0LmksMSk7cmVuZGVySW1ncygpO30pOwogIGlmKCQoJyNwZl9hZGRpbWcnKSkkKCcjcGZfYWRkaW1nJykub25jbGljaz0oKT0+JCgnI3BmX2ZpbGUnKS5jbGljaygpOwogfQogcmVuZGVySW1ncygpOwogJCgnI3BmX2ZpbGUnKS5vbmNoYW5nZT1hc3luYygpPT57CiAgY29uc3QgZj0kKCcjcGZfZmlsZScpLmZpbGVzWzBdOyBpZighZilyZXR1cm47CiAgaWYoZi5zaXplPjQqMTAyNCoxMDI0KXt0b2FzdCgn4Kab4Kas4Ka/IOCnqk1CIOCmj+CmsCDgppXgpq4g4Ka54Kak4KeHIOCmueCmrOCnhycsdHJ1ZSk7cmV0dXJuO30KICB0cnl7Y29uc3Qgcj1hd2FpdCBmZXRjaCgnL2FkbWluL2FwaS91cGxvYWQnLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOmYudHlwZSwnWC1DU1JGJzpDU1JGfSxib2R5OmZ9KTtjb25zdCBqPWF3YWl0IHIuanNvbigpO2lmKCFyLm9rKXRocm93IG5ldyBFcnJvcihqLmVycm9yKTtpbWFnZXMucHVzaChqLmZpbGUpO3JlbmRlckltZ3MoKTt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KICAkKCcjcGZfZmlsZScpLnZhbHVlPScnOwogfTsKIGZ1bmN0aW9uIHJlbmRlclZhcnMoKXsKICAkKCcjcGZfdmFycycpLmlubmVySFRNTD12YXJpYW50cy5tYXAoKHYsaSk9PmA8ZGl2IGNsYXNzPSJ2cm93MiI+PGlucHV0IHBsYWNlaG9sZGVyPSLgpqjgpr7gpq4gKOCmr+Cnh+CmruCmqDogTCkiIGRhdGEtdmk9IiR7aX0iIGRhdGEtdmY9ImxhYmVsIiB2YWx1ZT0iJHtlc2Modi5sYWJlbCl9Ij48aW5wdXQgcGxhY2Vob2xkZXI9IuCmpuCmvuCmriAo4KaQ4Kaa4KeN4Kab4Ka/4KaVKSIgZGF0YS12aT0iJHtpfSIgZGF0YS12Zj0icHJpY2UiIHZhbHVlPSIke3YucHJpY2V9IiBpbnB1dG1vZGU9Im51bWVyaWMiPjxpbnB1dCBwbGFjZWhvbGRlcj0i4Ka44KeN4Kaf4KaVIiBkYXRhLXZpPSIke2l9IiBkYXRhLXZmPSJzdG9jayIgdmFsdWU9IiR7di5zdG9ja30iIGlucHV0bW9kZT0ibnVtZXJpYyI+PGJ1dHRvbiBjbGFzcz0iYnRuIGRhbmdlciBzbSIgZGF0YS12ZD0iJHtpfSI+4pyVPC9idXR0b24+PC9kaXY+YCkuam9pbignJyk7CiAgJCgnI3BmX3N0b2Nrd3JhcCcpLnN0eWxlLmRpc3BsYXk9dmFyaWFudHMubGVuZ3RoPydub25lJzonZ3JpZCc7CiAgJCQoJyNwZl92YXJzIGlucHV0JykuZm9yRWFjaChpbnA9PmlucC5vbmlucHV0PSgpPT57dmFyaWFudHNbK2lucC5kYXRhc2V0LnZpXVtpbnAuZGF0YXNldC52Zl09aW5wLnZhbHVlO30pOwogICQkKCcjcGZfdmFycyBbZGF0YS12ZF0nKS5mb3JFYWNoKGI9PmIub25jbGljaz0oKT0+e3ZhcmlhbnRzLnNwbGljZSgrYi5kYXRhc2V0LnZkLDEpO3JlbmRlclZhcnMoKTt9KTsKIH0KIHJlbmRlclZhcnMoKTsKICQoJyNwZl92YWRkJykub25jbGljaz0oKT0+e3ZhcmlhbnRzLnB1c2goe2xhYmVsOicnLHByaWNlOicnLHN0b2NrOjB9KTtyZW5kZXJWYXJzKCk7fTsKICQoJyNtQ2FuY2VsJykub25jbGljaz1jbG9zZU1vZGFsOwogJCgnI21TYXZlJykub25jbGljaz1hc3luYygpPT57CiAgY2xlYXJFcnJzKCQoJyNtb2RhbEJvZHknKSk7CiAgY29uc3QgcGF5bG9hZD17dGl0bGU6JCgnI3BmX3RpdGxlJykudmFsdWUudHJpbSgpLGNhdGVnb3J5X2lkOiQoJyNwZl9jYXQnKS52YWx1ZSxwcmljZTokKCcjcGZfcHJpY2UnKS52YWx1ZSxzYWxlX3ByaWNlOiQoJyNwZl9zYWxlJykudmFsdWUsCiAgIHN0b2NrOiQoJyNwZl9zdG9jaycpLnZhbHVlLGRlc2NyaXB0aW9uOiQoJyNwZl9kZXNjJykudmFsdWUsc3BlY3M6JCgnI3BmX3NwZWNzJykudmFsdWUsaW1hZ2VzLAogICB2YXJpYW50czp2YXJpYW50cy5maWx0ZXIodj0+di5sYWJlbC50cmltKCkpLm1hcCh2PT4oe2xhYmVsOnYubGFiZWwudHJpbSgpLHByaWNlOnYucHJpY2U9PT0nJz9udWxsOnYucHJpY2Usc3RvY2s6di5zdG9ja3x8MH0pKSwKICAgZmVhdHVyZWQ6JCgnI3BmX2ZlYXQnKS5jaGVja2VkLGFjdGl2ZTokKCcjcGZfYWN0aXZlJykuY2hlY2tlZH07CiAgY29uc3QgYj0kKCcjbVNhdmUnKTtiLmRpc2FibGVkPXRydWU7Yi50ZXh0Q29udGVudD0n4Ka54Kaa4KeN4Kab4KeH4oCmJzsKICB0cnl7CiAgIGlmKGlkKWF3YWl0IGFwaSgnL2FkbWluL2FwaS9wcm9kdWN0cy8nK2lkLHttZXRob2Q6J1BVVCcsYm9keTpKU09OLnN0cmluZ2lmeShwYXlsb2FkKX0pOwogICBlbHNlIGF3YWl0IGFwaSgnL2FkbWluL2FwaS9wcm9kdWN0cycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShwYXlsb2FkKX0pOwogICB0b2FzdCgn4Kaq4Kaj4KeN4KavIOCmuOCmguCmsOCmleCnjeCmt+Cmv+CmpCDgprngpq/gprzgp4fgppvgp4cnKTtjbG9zZU1vZGFsKCk7bG9hZFByb2R1Y3RzKDEsZmFsc2UpOwogIH1jYXRjaChlKXt0b2FzdChlLm1lc3NhZ2UsdHJ1ZSk7Yi5kaXNhYmxlZD1mYWxzZTtiLnRleHRDb250ZW50PSfgprjgpoLgprDgppXgp43gprfgpqMg4KaV4Kaw4KeB4KaoJzt9CiB9Owp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4KaV4KeN4Kav4Ka+4Kaf4Ka+4KaX4Kaw4Ka/CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpyb3V0ZSgnY2F0ZWdvcmllcycsYXN5bmMoKT0+ewogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImNfYWRkIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxNHB4Ij4rIOCmqOCmpOCngeCmqCDgppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr88L2J1dHRvbj48ZGl2IGlkPSJjX2JvZHkiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PmA7CiAkKCcjY19hZGQnKS5vbmNsaWNrPSgpPT5jYXRNb2RhbCgpOwogYXdhaXQgbG9hZENhdHMoKTsKfSk7CmFzeW5jIGZ1bmN0aW9uIGxvYWRDYXRzKCl7CiBjb25zdCBkPWF3YWl0IGFwaSgnL2FkbWluL2FwaS9jYXRlZ29yaWVzJyk7CiAkKCcjY19ib2R5JykuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJ0Ymx3cmFwIj48dGFibGU+PHRoZWFkPjx0cj48dGg+4KaG4KaH4KaV4KaoPC90aD48dGg+4Kao4Ka+4KauPC90aD48dGg+4Kaq4Kaj4KeN4KavPC90aD48dGg+4KaV4KeN4Kaw4KauPC90aD48dGg+4KaF4Kas4Ka44KeN4Kal4Ka+PC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgPHRib2R5PiR7ZC5pdGVtcy5tYXAoYz0+YDx0cj48dGQgc3R5bGU9ImZvbnQtc2l6ZToyMHB4Ij4ke2VzYyhjLmljb24pfTwvdGQ+PHRkPiR7ZXNjKGMubmFtZSl9PC90ZD48dGQ+JHtjLm59PC90ZD48dGQ+JHtjLnNvcnR9PC90ZD48dGQ+JHtjLmFjdGl2ZT8n4Ka44KaV4KeN4Kaw4Ka/4Kav4Ka8Jzon4Kao4Ka/4Ka34KeN4KaV4KeN4Kaw4Ka/4Kav4Ka8J308L3RkPgogICA8dGQ+PGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtIiBkYXRhLWU9JyR7Yy5pZH0nPuCmuOCmruCnjeCmquCmvuCmpuCmqOCmvjwvYnV0dG9uPiA8YnV0dG9uIGNsYXNzPSJidG4gZGFuZ2VyIHNtIiBkYXRhLWQ9IiR7Yy5pZH0iPuCmruCngeCmm+CngeCmqDwvYnV0dG9uPjwvdGQ+PC90cj5gKS5qb2luKCcnKXx8Jzx0cj48dGQgY29sc3Bhbj0iNiIgY2xhc3M9ImVtcHR5Ij7gppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr8g4Kao4KeH4KaHPC90ZD48L3RyPid9PC90Ym9keT48L3RhYmxlPjwvZGl2PmA7CiAkJCgnI2NfYm9keSBbZGF0YS1lXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT5jYXRNb2RhbChkLml0ZW1zLmZpbmQoeD0+eC5pZD09Yi5kYXRhc2V0LmUpKSk7CiAkJCgnI2NfYm9keSBbZGF0YS1kXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPWFzeW5jKCk9PntpZighY29uZmlybSgn4Kau4KeB4Kab4KeHIOCmq+Cnh+CmsuCmpOCnhyDgpprgpr7gpqg/IOCmj+CmhyDgppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr/gprAg4Kaq4Kaj4KeN4Kav4KaX4KeB4Kay4KeLICLgppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr8g4Kao4KeH4KaHIiDgprngpq/gprzgp4cg4Kav4Ka+4Kas4KeH4KWkJykpcmV0dXJuO3RyeXthd2FpdCBhcGkoJy9hZG1pbi9hcGkvY2F0ZWdvcmllcy8nK2IuZGF0YXNldC5kLHttZXRob2Q6J0RFTEVURSd9KTt0b2FzdCgn4Kau4KeB4Kab4KeHIOCmq+Cnh+CmsuCmviDgprngpq/gprzgp4fgppvgp4cnKTtsb2FkQ2F0cygpO31jYXRjaChlKXt0b2FzdChlLm1lc3NhZ2UsdHJ1ZSk7fX0pOwp9CmZ1bmN0aW9uIGNhdE1vZGFsKGMpewogYz1jfHx7bmFtZTonJyxpY29uOifwn5uN77iPJyxzb3J0OjAsYWN0aXZlOnRydWV9Owogb3Blbk1vZGFsKGMuaWQ/J+CmleCnjeCmr+CmvuCmn+CmvuCml+CmsOCmvyDgprjgpq7gp43gpqrgpr7gpqbgpqjgpr4nOifgpqjgpqTgp4Hgpqgg4KaV4KeN4Kav4Ka+4Kaf4Ka+4KaX4Kaw4Ka/JywKICBgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kao4Ka+4KauICo8L3NwYW4+PGlucHV0IGlkPSJjZl9uYW1lIiB2YWx1ZT0iJHtlc2MoYy5uYW1lKX0iIG1heGxlbmd0aD0iNDAiPjwvZGl2PgogICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpobgpofgppXgpqggKOCmh+CmruCni+CmnOCmvyk8L3NwYW4+PGlucHV0IGlkPSJjZl9pY29uIiB2YWx1ZT0iJHtlc2MoYy5pY29uKX0iIG1heGxlbmd0aD0iOCI+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmleCnjeCmsOCmriAo4Kab4KeL4KafIOCmuOCmguCmluCnjeCmr+CmviDgpobgppfgp4cg4Kam4KeH4KaW4Ka+4Kas4KeHKTwvc3Bhbj48aW5wdXQgaWQ9ImNmX3NvcnQiIHR5cGU9InRleHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgdmFsdWU9IiR7Yy5zb3J0fSI+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYgY2hrIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJjZl9hY3RpdmUiICR7Yy5hY3RpdmUhPT1mYWxzZT8nY2hlY2tlZCc6Jyd9PjxzcGFuPuCmuOCmleCnjeCmsOCmv+Cmr+CmvDwvc3Bhbj48L2Rpdj5gLAogIGA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJtQ2FuY2VsIj7gpqzgpr7gpqTgpr/gprI8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJtU2F2ZSI+4Ka44KaC4Kaw4KaV4KeN4Ka34KajIOCmleCmsOCngeCmqDwvYnV0dG9uPmApOwogJCgnI21DYW5jZWwnKS5vbmNsaWNrPWNsb3NlTW9kYWw7CiAkKCcjbVNhdmUnKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBwYXlsb2FkPXtuYW1lOiQoJyNjZl9uYW1lJykudmFsdWUudHJpbSgpLGljb246JCgnI2NmX2ljb24nKS52YWx1ZS50cmltKCl8fCfwn5uN77iPJyxzb3J0OiQoJyNjZl9zb3J0JykudmFsdWUsYWN0aXZlOiQoJyNjZl9hY3RpdmUnKS5jaGVja2VkfTsKICB0cnl7aWYoYy5pZClhd2FpdCBhcGkoJy9hZG1pbi9hcGkvY2F0ZWdvcmllcy8nK2MuaWQse21ldGhvZDonUFVUJyxib2R5OkpTT04uc3RyaW5naWZ5KHBheWxvYWQpfSk7ZWxzZSBhd2FpdCBhcGkoJy9hZG1pbi9hcGkvY2F0ZWdvcmllcycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShwYXlsb2FkKX0pO3RvYXN0KCfgprjgpoLgprDgppXgp43gprfgpr/gpqQg4Ka54Kav4Ka84KeH4Kab4KeHJyk7Y2xvc2VNb2RhbCgpO2xvYWRDYXRzKCk7fQogIGNhdGNoKGUpe3RvYXN0KGUubWVzc2FnZSx0cnVlKTt9CiB9Owp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4KaV4KeB4Kaq4KaoCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpyb3V0ZSgnY291cG9ucycsYXN5bmMoKT0+ewogJCgnI2NvbnRlbnQnKS5pbm5lckhUTUw9YDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImtfYWRkIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxNHB4Ij4rIOCmqOCmpOCngeCmqCDgppXgp4Hgpqrgpqg8L2J1dHRvbj48ZGl2IGlkPSJrX2JvZHkiPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PmA7CiAkKCcja19hZGQnKS5vbmNsaWNrPSgpPT5jb3Vwb25Nb2RhbCgpOwogYXdhaXQgbG9hZENvdXBvbnMoKTsKfSk7CmFzeW5jIGZ1bmN0aW9uIGxvYWRDb3Vwb25zKCl7CiBjb25zdCBkPWF3YWl0IGFwaSgnL2FkbWluL2FwaS9jb3Vwb25zJyk7CiAkKCcja19ib2R5JykuaW5uZXJIVE1MPWA8ZGl2IGNsYXNzPSJ0Ymx3cmFwIj48dGFibGU+PHRoZWFkPjx0cj48dGg+4KaV4KeL4KahPC90aD48dGg+4Kab4Ka+4Kah4Ka8PC90aD48dGg+4Ka44Kaw4KeN4Kas4Kao4Ka/4Kau4KeN4KaoIOCmheCmsOCnjeCmoeCmvuCmsDwvdGg+PHRoPuCmrOCnjeCmr+CmrOCmueCmvuCmsDwvdGg+PHRoPuCmruCnh+Cmr+CmvOCmvuCmpjwvdGg+PHRoPuCmheCmrOCmuOCnjeCmpeCmvjwvdGg+PHRoPjwvdGg+PC90cj48L3RoZWFkPgogIDx0Ym9keT4ke2QuaXRlbXMubWFwKGM9PmA8dHI+PHRkIGNsYXNzPSJtb25vIj4ke2VzYyhjLmNvZGUpfTwvdGQ+PHRkPiR7Yy5raW5kPT09J3BlcmNlbnQnP2MudmFsdWUrJyUnOm1vbmV5KGMudmFsdWUpfTwvdGQ+PHRkPiR7bW9uZXkoYy5taW5fb3JkZXIpfTwvdGQ+PHRkPiR7Yy51c2VkfSR7Yy5tYXhfdXNlcz8nLycrYy5tYXhfdXNlczonJ308L3RkPjx0ZD4ke2MuZXhwaXJlc3x8J+KAlCd9PC90ZD48dGQ+JHtjLmFjdGl2ZT8n4Ka44KaV4KeN4Kaw4Ka/4Kav4Ka8Jzon4Kao4Ka/4Ka34KeN4KaV4KeN4Kaw4Ka/4Kav4Ka8J308L3RkPgogICA8dGQ+PGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtIiBkYXRhLWU9IiR7Yy5pZH0iPuCmuOCmruCnjeCmquCmvuCmpuCmqOCmvjwvYnV0dG9uPiA8YnV0dG9uIGNsYXNzPSJidG4gZGFuZ2VyIHNtIiBkYXRhLWQ9IiR7Yy5pZH0iPuCmruCngeCmm+CngeCmqDwvYnV0dG9uPjwvdGQ+PC90cj5gKS5qb2luKCcnKXx8Jzx0cj48dGQgY29sc3Bhbj0iNyIgY2xhc3M9ImVtcHR5Ij7gppXgp4Hgpqrgpqgg4Kao4KeH4KaHPC90ZD48L3RyPid9PC90Ym9keT48L3RhYmxlPjwvZGl2PmA7CiAkJCgnI2tfYm9keSBbZGF0YS1lXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPSgpPT5jb3Vwb25Nb2RhbChkLml0ZW1zLmZpbmQoeD0+eC5pZD09Yi5kYXRhc2V0LmUpKSk7CiAkJCgnI2tfYm9keSBbZGF0YS1kXScpLmZvckVhY2goYj0+Yi5vbmNsaWNrPWFzeW5jKCk9PntpZighY29uZmlybSgn4KaV4KeB4Kaq4Kao4Kaf4Ka/IOCmruCngeCmm+CnhyDgpqvgp4fgprLgpqTgp4cg4Kaa4Ka+4KaoPycpKXJldHVybjt0cnl7YXdhaXQgYXBpKCcvYWRtaW4vYXBpL2NvdXBvbnMvJytiLmRhdGFzZXQuZCx7bWV0aG9kOidERUxFVEUnfSk7dG9hc3QoJ+CmruCngeCmm+CnhyDgpqvgp4fgprLgpr4g4Ka54Kav4Ka84KeH4Kab4KeHJyk7bG9hZENvdXBvbnMoKTt9Y2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO319KTsKfQpmdW5jdGlvbiBjb3Vwb25Nb2RhbChjKXsKIGM9Y3x8e2NvZGU6Jycsa2luZDoncGVyY2VudCcsdmFsdWU6JycsbWluX29yZGVyOjAsbWF4X3VzZXM6MCxleHBpcmVzOicnLGFjdGl2ZTp0cnVlfTsKIG9wZW5Nb2RhbChjLmlkPyfgppXgp4Hgpqrgpqgg4Ka44Kau4KeN4Kaq4Ka+4Kam4Kao4Ka+Jzon4Kao4Kak4KeB4KaoIOCmleCngeCmquCmqCcsCiAgYDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmleCngeCmquCmqCDgppXgp4vgpqEgKjwvc3Bhbj48aW5wdXQgaWQ9ImtmX2NvZGUiIHZhbHVlPSIke2VzYyhjLmNvZGUpfSIgbWF4bGVuZ3RoPSIyMCIgc3R5bGU9InRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZSIgJHtjLmlkPycnOicnfT48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZjIiPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmp+CmsOCmqDwvc3Bhbj48c2VsZWN0IGlkPSJrZl9raW5kIj48b3B0aW9uIHZhbHVlPSJwZXJjZW50IiAke2Mua2luZD09PSdwZXJjZW50Jz8nc2VsZWN0ZWQnOicnfT7gprbgpqTgpr7gpoLgprYgKCUpPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iZml4ZWQiICR7Yy5raW5kPT09J2ZpeGVkJz8nc2VsZWN0ZWQnOicnfT7gpqjgpr/gprDgp43gpqbgpr/gprfgp43gpp8g4Kaf4Ka+4KaV4Ka+PC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqrgprDgpr/gpq7gpr7gpqMgKjwvc3Bhbj48aW5wdXQgaWQ9ImtmX3ZhbHVlIiB0eXBlPSJ0ZXh0IiBpbnB1dG1vZGU9Im51bWVyaWMiIHZhbHVlPSIke2MudmFsdWV9Ij48L2Rpdj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZjIiPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmuOCmsOCnjeCmrOCmqOCmv+CmruCnjeCmqCDgpoXgprDgp43gpqHgpr7gprA8L3NwYW4+PGlucHV0IGlkPSJrZl9taW4iIHR5cGU9InRleHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgdmFsdWU9IiR7Yy5taW5fb3JkZXJ9Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmuOCmsOCnjeCmrOCni+CmmuCnjeCmmiDgpqzgp43gpq/gpqzgprngpr7gprAgKOCnpiA9IOCmuOCngOCmruCmvuCmueCngOCmqCk8L3NwYW4+PGlucHV0IGlkPSJrZl9tYXgiIHR5cGU9InRleHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgdmFsdWU9IiR7Yy5tYXhfdXNlc30iPjwvZGl2PjwvZGl2PgogICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpq7gp4fgpq/gprzgpr7gpqYg4Ka24KeH4Ka34KeH4KawIOCmpOCmvuCmsOCmv+CmliAo4KaQ4Kaa4KeN4Kab4Ka/4KaVKTwvc3Bhbj48aW5wdXQgaWQ9ImtmX2V4cCIgdHlwZT0iZGF0ZSIgdmFsdWU9IiR7Yy5leHBpcmVzfSI+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYgY2hrIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJrZl9hY3RpdmUiICR7Yy5hY3RpdmUhPT1mYWxzZT8nY2hlY2tlZCc6Jyd9PjxzcGFuPuCmuOCmleCnjeCmsOCmv+Cmr+CmvDwvc3Bhbj48L2Rpdj5gLAogIGA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJtQ2FuY2VsIj7gpqzgpr7gpqTgpr/gprI8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJtU2F2ZSI+4Ka44KaC4Kaw4KaV4KeN4Ka34KajIOCmleCmsOCngeCmqDwvYnV0dG9uPmApOwogJCgnI21DYW5jZWwnKS5vbmNsaWNrPWNsb3NlTW9kYWw7CiAkKCcjbVNhdmUnKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBwYXlsb2FkPXtjb2RlOiQoJyNrZl9jb2RlJykudmFsdWUudHJpbSgpLGtpbmQ6JCgnI2tmX2tpbmQnKS52YWx1ZSx2YWx1ZTokKCcja2ZfdmFsdWUnKS52YWx1ZSxtaW5fb3JkZXI6JCgnI2tmX21pbicpLnZhbHVlLG1heF91c2VzOiQoJyNrZl9tYXgnKS52YWx1ZSxleHBpcmVzOiQoJyNrZl9leHAnKS52YWx1ZSxhY3RpdmU6JCgnI2tmX2FjdGl2ZScpLmNoZWNrZWR9OwogIHRyeXtpZihjLmlkKWF3YWl0IGFwaSgnL2FkbWluL2FwaS9jb3Vwb25zLycrYy5pZCx7bWV0aG9kOidQVVQnLGJvZHk6SlNPTi5zdHJpbmdpZnkocGF5bG9hZCl9KTtlbHNlIGF3YWl0IGFwaSgnL2FkbWluL2FwaS9jb3Vwb25zJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHBheWxvYWQpfSk7dG9hc3QoJ+CmuOCmguCmsOCmleCnjeCmt+Cmv+CmpCDgprngpq/gprzgp4fgppvgp4cnKTtjbG9zZU1vZGFsKCk7bG9hZENvdXBvbnMoKTt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KIH07Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICDgpqzgp43gpq/gpr7gpqjgpr7gprAKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCnJvdXRlKCdiYW5uZXJzJyxhc3luYygpPT57CiAkKCcjY29udGVudCcpLmlubmVySFRNTD1gPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0iYl9hZGQiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjE0cHgiPisg4Kao4Kak4KeB4KaoIOCmrOCnjeCmr+CmvuCmqOCmvuCmsDwvYnV0dG9uPjxkaXYgaWQ9ImJfYm9keSI+PGRpdiBjbGFzcz0ic3BpbiI+PC9kaXY+PC9kaXY+YDsKICQoJyNiX2FkZCcpLm9uY2xpY2s9KCk9PmJhbm5lck1vZGFsKCk7CiBhd2FpdCBsb2FkQmFubmVycygpOwp9KTsKYXN5bmMgZnVuY3Rpb24gbG9hZEJhbm5lcnMoKXsKIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYWRtaW4vYXBpL2Jhbm5lcnMnKTsKICQoJyNiX2JvZHknKS5pbm5lckhUTUw9YDxkaXYgY2xhc3M9ImdyaWQgZzIiPiR7ZC5pdGVtcy5tYXAoYj0+YDxkaXYgY2xhc3M9ImNhcmQiIHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjEycHg7YWxpZ24taXRlbXM6Y2VudGVyIj4KICA8ZGl2IHN0eWxlPSJ3aWR0aDo4MHB4O2hlaWdodDo1MHB4O2JvcmRlci1yYWRpdXM6OHB4O2JhY2tncm91bmQ6JHtlc2MoYi5jb2xvcil9IGNlbnRlci9jb3ZlciBuby1yZXBlYXQke2IuaW1hZ2U/YCx1cmwoJy91cGxvYWRzLyR7ZXNjKGIuaW1hZ2UpfScpYDonJ30iPjwvZGl2PgogIDxkaXYgc3R5bGU9ImZsZXg6MSI+PGI+JHtlc2MoYi50aXRsZSl9PC9iPjxicj48c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTIuNXB4Ij4ke2VzYyhiLnN1YnRpdGxlKXx8J+KAlCd9PC9zcGFuPjxicj4ke2IuYWN0aXZlPyfgprjgppXgp43gprDgpr/gpq/gprwnOifgpqjgpr/gprfgp43gppXgp43gprDgpr/gpq/gprwnfTwvZGl2PgogIDxkaXY+PGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtIiBkYXRhLWU9IiR7Yi5pZH0iPuCmuOCmruCnjeCmquCmvuCmpuCmqOCmvjwvYnV0dG9uPjxicj48YnV0dG9uIGNsYXNzPSJidG4gZGFuZ2VyIHNtIiBkYXRhLWQ9IiR7Yi5pZH0iIHN0eWxlPSJtYXJnaW4tdG9wOjZweCI+4Kau4KeB4Kab4KeB4KaoPC9idXR0b24+PC9kaXY+PC9kaXY+YCkuam9pbignJyl8fCc8cCBjbGFzcz0iZW1wdHkiPuCmrOCnjeCmr+CmvuCmqOCmvuCmsCDgpqjgp4fgpoc8L3A+J308L2Rpdj5gOwogJCQoJyNiX2JvZHkgW2RhdGEtZV0nKS5mb3JFYWNoKHg9Pngub25jbGljaz0oKT0+YmFubmVyTW9kYWwoZC5pdGVtcy5maW5kKHk9PnkuaWQ9PXguZGF0YXNldC5lKSkpOwogJCQoJyNiX2JvZHkgW2RhdGEtZF0nKS5mb3JFYWNoKHg9Pngub25jbGljaz1hc3luYygpPT57aWYoIWNvbmZpcm0oJ+CmruCngeCmm+CnhyDgpqvgp4fgprLgpqTgp4cg4Kaa4Ka+4KaoPycpKXJldHVybjt0cnl7YXdhaXQgYXBpKCcvYWRtaW4vYXBpL2Jhbm5lcnMvJyt4LmRhdGFzZXQuZCx7bWV0aG9kOidERUxFVEUnfSk7dG9hc3QoJ+CmruCngeCmm+CnhyDgpqvgp4fgprLgpr4g4Ka54Kav4Ka84KeH4Kab4KeHJyk7bG9hZEJhbm5lcnMoKTt9Y2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO319KTsKfQpmdW5jdGlvbiBiYW5uZXJNb2RhbChiKXsKIGI9Ynx8e3RpdGxlOicnLHN1YnRpdGxlOicnLGxpbms6JycsaW1hZ2U6JycsY29sb3I6JyNGMDVBMjgnLHNvcnQ6MCxhY3RpdmU6dHJ1ZX07CiBvcGVuTW9kYWwoYi5pZD8n4Kas4KeN4Kav4Ka+4Kao4Ka+4KawIOCmuOCmruCnjeCmquCmvuCmpuCmqOCmvic6J+CmqOCmpOCngeCmqCDgpqzgp43gpq/gpr7gpqjgpr7gprAnLAogIGA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gprbgpr/gprDgp4vgpqjgpr7gpq4gKjwvc3Bhbj48aW5wdXQgaWQ9ImJmX3RpdGxlIiB2YWx1ZT0iJHtlc2MoYi50aXRsZSl9IiBtYXhsZW5ndGg9IjgwIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4KaJ4Kaq4Ka24Ka/4Kaw4KeL4Kao4Ka+4KauPC9zcGFuPjxpbnB1dCBpZD0iYmZfc3ViIiB2YWx1ZT0iJHtlc2MoYi5zdWJ0aXRsZSl9IiBtYXhsZW5ndGg9IjEyMCI+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmsuCmv+CmguCmlSAo4Kav4KeH4Kau4KaoIC9zaG9wP2RlYWw9MSk8L3NwYW4+PGlucHV0IGlkPSJiZl9saW5rIiB2YWx1ZT0iJHtlc2MoYi5saW5rKX0iIG1heGxlbmd0aD0iMjAwIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kas4KeN4Kav4Ka+4KaV4KaX4KeN4Kaw4Ka+4KaJ4Kao4KeN4KahIOCmsOCmgjwvc3Bhbj48ZGl2IGNsYXNzPSJjb2xvcnJvdyI+PGlucHV0IHR5cGU9ImNvbG9yIiBpZD0iYmZfY29sb3IiIHZhbHVlPSIke2VzYyhiLmNvbG9yKX0iPjxzcGFuIGNsYXNzPSJzd2F0Y2giIGlkPSJiZl9zdyIgc3R5bGU9ImJhY2tncm91bmQ6JHtlc2MoYi5jb2xvcil9Ij48L3NwYW4+PC9kaXY+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmm+CmrOCmvyAo4KaQ4Kaa4KeN4Kab4Ka/4KaVKTwvc3Bhbj48ZGl2IGNsYXNzPSJpbWdwaWNrIiBpZD0iYmZfaW1ncyI+PC9kaXY+PGlucHV0IHR5cGU9ImZpbGUiIGlkPSJiZl9maWxlIiBhY2NlcHQ9ImltYWdlLyoiIGhpZGRlbj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4KaV4KeN4Kaw4KauPC9zcGFuPjxpbnB1dCBpZD0iYmZfc29ydCIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtiLnNvcnR9Ij48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiBjaGsiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9ImJmX2FjdGl2ZSIgJHtiLmFjdGl2ZSE9PWZhbHNlPydjaGVja2VkJzonJ30+PHNwYW4+4Ka44KaV4KeN4Kaw4Ka/4Kav4Ka8PC9zcGFuPjwvZGl2PmAsCiAgYDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9Im1DYW5jZWwiPuCmrOCmvuCmpOCmv+CmsjwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9Im1TYXZlIj7gprjgpoLgprDgppXgp43gprfgpqMg4KaV4Kaw4KeB4KaoPC9idXR0b24+YCk7CiBsZXQgaW1nPWIuaW1hZ2U7CiBmdW5jdGlvbiByZW5kZXJCSSgpeyQoJyNiZl9pbWdzJykuaW5uZXJIVE1MPWltZz9gPGRpdiBjbGFzcz0iaW1ndGlsZSIgc3R5bGU9ImJhY2tncm91bmQtaW1hZ2U6dXJsKCcvdXBsb2Fkcy8ke2VzYyhpbWcpfScpIj48YnV0dG9uIGlkPSJiZl9ybSI+4pyVPC9idXR0b24+PC9kaXY+YDpgPGRpdiBjbGFzcz0iaW1nYWRkIiBpZD0iYmZfYWRkIj4rPC9kaXY+YDsKICBpZigkKCcjYmZfYWRkJykpJCgnI2JmX2FkZCcpLm9uY2xpY2s9KCk9PiQoJyNiZl9maWxlJykuY2xpY2soKTsgaWYoJCgnI2JmX3JtJykpJCgnI2JmX3JtJykub25jbGljaz0oKT0+e2ltZz0nJztyZW5kZXJCSSgpO307fQogcmVuZGVyQkkoKTsKICQoJyNiZl9jb2xvcicpLm9uaW5wdXQ9KCk9PnskKCcjYmZfc3cnKS5zdHlsZS5iYWNrZ3JvdW5kPSQoJyNiZl9jb2xvcicpLnZhbHVlO307CiAkKCcjYmZfZmlsZScpLm9uY2hhbmdlPWFzeW5jKCk9PnsKICBjb25zdCBmPSQoJyNiZl9maWxlJykuZmlsZXNbMF07IGlmKCFmKXJldHVybjsKICB0cnl7Y29uc3Qgcj1hd2FpdCBmZXRjaCgnL2FkbWluL2FwaS91cGxvYWQnLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOmYudHlwZSwnWC1DU1JGJzpDU1JGfSxib2R5OmZ9KTtjb25zdCBqPWF3YWl0IHIuanNvbigpO2lmKCFyLm9rKXRocm93IG5ldyBFcnJvcihqLmVycm9yKTtpbWc9ai5maWxlO3JlbmRlckJJKCk7fWNhdGNoKGUpe3RvYXN0KGUubWVzc2FnZSx0cnVlKTt9CiB9OwogJCgnI21DYW5jZWwnKS5vbmNsaWNrPWNsb3NlTW9kYWw7CiAkKCcjbVNhdmUnKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBwYXlsb2FkPXt0aXRsZTokKCcjYmZfdGl0bGUnKS52YWx1ZS50cmltKCksc3VidGl0bGU6JCgnI2JmX3N1YicpLnZhbHVlLnRyaW0oKSxsaW5rOiQoJyNiZl9saW5rJykudmFsdWUudHJpbSgpLGltYWdlOmltZyxjb2xvcjokKCcjYmZfY29sb3InKS52YWx1ZSxzb3J0OiQoJyNiZl9zb3J0JykudmFsdWUsYWN0aXZlOiQoJyNiZl9hY3RpdmUnKS5jaGVja2VkfTsKICB0cnl7aWYoYi5pZClhd2FpdCBhcGkoJy9hZG1pbi9hcGkvYmFubmVycy8nK2IuaWQse21ldGhvZDonUFVUJyxib2R5OkpTT04uc3RyaW5naWZ5KHBheWxvYWQpfSk7ZWxzZSBhd2FpdCBhcGkoJy9hZG1pbi9hcGkvYmFubmVycycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShwYXlsb2FkKX0pO3RvYXN0KCfgprjgpoLgprDgppXgp43gprfgpr/gpqQg4Ka54Kav4Ka84KeH4Kab4KeHJyk7Y2xvc2VNb2RhbCgpO2xvYWRCYW5uZXJzKCk7fQogIGNhdGNoKGUpe3RvYXN0KGUubWVzc2FnZSx0cnVlKTt9CiB9Owp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg4Ka44KeH4Kaf4Ka/4KaC4Ka4CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpyb3V0ZSgnc2V0dGluZ3MnLGFzeW5jKCk9PnsKIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYWRtaW4vYXBpL3NldHRpbmdzJyk7CiBjb25zdCBTPWQuc2V0dGluZ3M7CiAkKCcjY29udGVudCcpLmlubmVySFRNTD1gCiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgzPuCmpuCni+CmleCmvuCmqOCnh+CmsCDgpqTgpqXgp43gpq88L2gzPgogICA8ZGl2IGNsYXNzPSJmMiI+PGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kam4KeL4KaV4Ka+4Kao4KeH4KawIOCmqOCmvuCmriAqPC9zcGFuPjxpbnB1dCBpZD0ic19uYW1lIiB2YWx1ZT0iJHtlc2MoUy5zaG9wX25hbWUpfSIgbWF4bGVuZ3RoPSI4MCI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqzgp43gprDgp43gpq/gpr7gpqjgp43gpqEg4Kaw4KaCPC9zcGFuPjxkaXYgY2xhc3M9ImNvbG9ycm93Ij48aW5wdXQgdHlwZT0iY29sb3IiIGlkPSJzX2JyYW5kIiB2YWx1ZT0iJHtlc2MoUy5icmFuZCl9Ij48c3BhbiBjbGFzcz0ic3dhdGNoIiBpZD0ic19zdyIgc3R5bGU9ImJhY2tncm91bmQ6JHtlc2MoUy5icmFuZCl9Ij48L3NwYW4+PC9kaXY+PC9kaXY+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmn+CnjeCmr+CmvuCml+CmsuCmvuCmh+CmqDwvc3Bhbj48aW5wdXQgaWQ9InNfdGFnIiB2YWx1ZT0iJHtlc2MoUy50YWdsaW5lKX0iIG1heGxlbmd0aD0iMTUwIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Ka24KeA4Kaw4KeN4Ka3IOCmqOCni+Cmn+Cmv+CmtiDgpqzgpr7gprA8L3NwYW4+PGlucHV0IGlkPSJzX25vdGljZSIgdmFsdWU9IiR7ZXNjKFMubm90aWNlKX0iIG1heGxlbmd0aD0iMTUwIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZjIiPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmq+Cni+CmqDwvc3Bhbj48aW5wdXQgaWQ9InNfcGhvbmUiIHZhbHVlPSIke2VzYyhTLnBob25lKX0iPjwvZGl2PjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmueCni+Cmr+CmvOCmvuCmn+CmuOCmheCnjeCmr+CmvuCmqiDgpqjgpq7gp43gpqzgprA8L3NwYW4+PGlucHV0IGlkPSJzX3dhIiB2YWx1ZT0iJHtlc2MoUy53aGF0c2FwcCl9IiBwbGFjZWhvbGRlcj0iMDFYWFhYWFhYWFgiPjwvZGl2PjwvZGl2PgogICA8ZGl2IGNsYXNzPSJmMiI+PGRpdiBjbGFzcz0iZiI+PHNwYW4+4KaH4Kau4KeH4KaH4KayPC9zcGFuPjxpbnB1dCBpZD0ic19lbWFpbCIgdmFsdWU9IiR7ZXNjKFMuZW1haWwpfSI+PC9kaXY+PGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kag4Ka/4KaV4Ka+4Kao4Ka+PC9zcGFuPjxpbnB1dCBpZD0ic19hZGRyIiB2YWx1ZT0iJHtlc2MoUy5hZGRyZXNzKX0iPjwvZGl2PjwvZGl2PjwvZGl2PgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqHgp4fgprLgpr/gpq3gpr7gprDgpr88L2gzPgogICA8ZGl2IGNsYXNzPSJmMiI+PGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kai4Ka+4KaV4Ka+4KawIOCmreCnh+CmpOCmsOCnhyDgpprgpr7gprDgp43gppwgKOCnsyk8L3NwYW4+PGlucHV0IGlkPSJzX3NoZCIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtTLnNoaXBfZGhha2F9Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmouCmvuCmleCmvuCmsCDgpqzgpr7gpofgprDgp4cg4Kaa4Ka+4Kaw4KeN4KacICjgp7MpPC9zcGFuPjxpbnB1dCBpZD0ic19zaG8iIHR5cGU9InRleHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgdmFsdWU9IiR7Uy5zaGlwX291dHNpZGV9Ij48L2Rpdj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZjIiPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmj+CmsCDgpqzgp4fgprbgpr8g4KaF4Kaw4KeN4Kah4Ka+4Kaw4KeHIOCmq+CnjeCmsOCmvyDgpqHgp4fgprLgpr/gpq3gpr7gprDgpr8gKOCnpiA9IOCmrOCmqOCnjeCmpyk8L3NwYW4+PGlucHV0IGlkPSJzX2ZyZWUiIHR5cGU9InRleHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgdmFsdWU9IiR7Uy5mcmVlX292ZXJ9Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmuOCmsOCnjeCmrOCmqOCmv+CmruCnjeCmqCDgpoXgprDgp43gpqHgpr7gprAgKOCnsyk8L3NwYW4+PGlucHV0IGlkPSJzX21pbiIgdHlwZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiB2YWx1ZT0iJHtTLm1pbl9vcmRlcn0iPjwvZGl2PjwvZGl2PjwvZGl2PgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMz7gpqrgp4fgpq7gp4fgpqjgp43gpp88L2gzPgogICA8ZGl2IGNsYXNzPSJmIGNoayI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0ic19jb2QiICR7Uy5jb2Q9PT0nMSc/J2NoZWNrZWQnOicnfT48c3Bhbj7gppXgp43gpq/gpr7gprYg4KaF4KaoIOCmoeCnh+CmsuCmv+CmreCmvuCmsOCmvyDgpprgpr7gprLgp4E8L3NwYW4+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYyIj48ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqzgpr/gppXgpr7gprYg4Kao4Kau4KeN4Kas4KawICjgpqvgpr7gpoHgppXgpr4gPSDgpqzgpqjgp43gpqcpPC9zcGFuPjxpbnB1dCBpZD0ic19ia2FzaCIgdmFsdWU9IiR7ZXNjKFMuYmthc2gpfSI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmIj48c3Bhbj7gpqjgppfgpqYg4Kao4Kau4KeN4Kas4KawICjgpqvgpr7gpoHgppXgpr4gPSDgpqzgpqjgp43gpqcpPC9zcGFuPjxpbnB1dCBpZD0ic19uYWdhZCIgdmFsdWU9IiR7ZXNjKFMubmFnYWQpfSI+PC9kaXY+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmquCnh+CmruCnh+CmqOCnjeCmnyDgpqjgpr/gprDgp43gpqbgp4fgprbgpqjgpr48L3NwYW4+PGlucHV0IGlkPSJzX3BheW5vdGUiIHZhbHVlPSIke2VzYyhTLnBheV9ub3RlKX0iIG1heGxlbmd0aD0iMjAwIj48L2Rpdj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Kaq4Ka+4Kak4Ka+4KawIOCmsuCnh+CmluCmvjwvaDM+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmhuCmruCmvuCmpuCnh+CmsCDgprjgpq7gp43gpqrgprDgp43gppXgp4c8L3NwYW4+PHRleHRhcmVhIGlkPSJzX2Fib3V0IiBtYXhsZW5ndGg9IjIwMDAwIj4ke2VzYyhTLnBhZ2VfYWJvdXQpfTwvdGV4dGFyZWE+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmtuCmsOCnjeCmpOCmvuCmrOCmsuCmvzwvc3Bhbj48dGV4dGFyZWEgaWQ9InNfdGVybXMiIG1heGxlbmd0aD0iMjAwMDAiPiR7ZXNjKFMucGFnZV90ZXJtcyl9PC90ZXh0YXJlYT48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kar4KeH4Kaw4KakIOCmqOCngOCmpOCmvzwvc3Bhbj48dGV4dGFyZWEgaWQ9InNfcmV0dXJucyIgbWF4bGVuZ3RoPSIyMDAwMCI+JHtlc2MoUy5wYWdlX3JldHVybnMpfTwvdGV4dGFyZWE+PC9kaXY+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCml+Cni+CmquCmqOCngOCmr+CmvOCmpOCmviDgpqjgp4DgpqTgpr88L3NwYW4+PHRleHRhcmVhIGlkPSJzX3ByaXZhY3kiIG1heGxlbmd0aD0iMjAwMDAiPiR7ZXNjKFMucGFnZV9wcml2YWN5KX08L3RleHRhcmVhPjwvZGl2PjwvZGl2PgogIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InNfc2F2ZSI+4Ka44KasIOCmuOCmguCmsOCmleCnjeCmt+CmoyDgppXgprDgp4Hgpqg8L2J1dHRvbj5gOwogJCgnI3NfYnJhbmQnKS5vbmlucHV0PSgpPT57JCgnI3Nfc3cnKS5zdHlsZS5iYWNrZ3JvdW5kPSQoJyNzX2JyYW5kJykudmFsdWU7fTsKICQoJyNzX3NhdmUnKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBwYXlsb2FkPXtzaG9wX25hbWU6JCgnI3NfbmFtZScpLnZhbHVlLnRyaW0oKSxicmFuZDokKCcjc19icmFuZCcpLnZhbHVlLHRhZ2xpbmU6JCgnI3NfdGFnJykudmFsdWUudHJpbSgpLG5vdGljZTokKCcjc19ub3RpY2UnKS52YWx1ZS50cmltKCksCiAgIHBob25lOiQoJyNzX3Bob25lJykudmFsdWUudHJpbSgpLHdoYXRzYXBwOiQoJyNzX3dhJykudmFsdWUudHJpbSgpLGVtYWlsOiQoJyNzX2VtYWlsJykudmFsdWUudHJpbSgpLGFkZHJlc3M6JCgnI3NfYWRkcicpLnZhbHVlLnRyaW0oKSwKICAgc2hpcF9kaGFrYTokKCcjc19zaGQnKS52YWx1ZSxzaGlwX291dHNpZGU6JCgnI3Nfc2hvJykudmFsdWUsZnJlZV9vdmVyOiQoJyNzX2ZyZWUnKS52YWx1ZSxtaW5fb3JkZXI6JCgnI3NfbWluJykudmFsdWUsCiAgIGNvZDokKCcjc19jb2QnKS5jaGVja2VkLGJrYXNoOiQoJyNzX2JrYXNoJykudmFsdWUudHJpbSgpLG5hZ2FkOiQoJyNzX25hZ2FkJykudmFsdWUudHJpbSgpLHBheV9ub3RlOiQoJyNzX3BheW5vdGUnKS52YWx1ZS50cmltKCksCiAgIHBhZ2VfYWJvdXQ6JCgnI3NfYWJvdXQnKS52YWx1ZSxwYWdlX3Rlcm1zOiQoJyNzX3Rlcm1zJykudmFsdWUscGFnZV9yZXR1cm5zOiQoJyNzX3JldHVybnMnKS52YWx1ZSxwYWdlX3ByaXZhY3k6JCgnI3NfcHJpdmFjeScpLnZhbHVlfTsKICBjb25zdCBiPSQoJyNzX3NhdmUnKTtiLmRpc2FibGVkPXRydWU7Yi50ZXh0Q29udGVudD0n4Ka54Kaa4KeN4Kab4KeH4oCmJzsKICB0cnl7YXdhaXQgYXBpKCcvYWRtaW4vYXBpL3NldHRpbmdzJyx7bWV0aG9kOidQVVQnLGJvZHk6SlNPTi5zdHJpbmdpZnkocGF5bG9hZCl9KTt0b2FzdCgn4Ka44KeH4Kaf4Ka/4KaC4Ka4IOCmuOCmguCmsOCmleCnjeCmt+Cmv+CmpCDgprngpq/gprzgp4fgppvgp4cnKTt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KICBiLmRpc2FibGVkPWZhbHNlO2IudGV4dENvbnRlbnQ9J+CmuOCmrCDgprjgpoLgprDgppXgp43gprfgpqMg4KaV4Kaw4KeB4KaoJzsKIH07Cn0pOwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmqOCmv+CmsOCmvuCmquCmpOCnjeCmpOCmvgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8Kcm91dGUoJ3NlY3VyaXR5Jyxhc3luYygpPT57CiBjb25zdCBtZT1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvbWUnKTsKIE1FLnRvdHBfb249bWUudG90cF9vbjsKICQoJyNjb250ZW50JykuaW5uZXJIVE1MPWAKICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Kaq4Ka+4Ka44KaT4Kav4Ka84Ka+4Kaw4KeN4KahIOCmquCmsOCmv+CmrOCmsOCnjeCmpOCmqDwvaDM+CiAgIDxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmrOCmsOCnjeCmpOCmruCmvuCmqCDgpqrgpr7gprjgppPgpq/gprzgpr7gprDgp43gpqE8L3NwYW4+PGlucHV0IGlkPSJwd19jdXIiIHR5cGU9InBhc3N3b3JkIj48L2Rpdj4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4Kao4Kak4KeB4KaoIOCmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoTwvc3Bhbj48aW5wdXQgaWQ9InB3X25ldyIgdHlwZT0icGFzc3dvcmQiPjwvZGl2PgogICA8cCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW46LTZweCAwIDEycHgiPuCmleCmruCmquCmleCnjeCmt+CnhyDgp6fgp6Yg4KaF4KaV4KeN4Ka34KawLCDgppvgp4vgpp8t4Kas4Kah4Ka8IOCmueCmvuCmpOCnh+CmsCDgpoXgppXgp43gprfgprAsIOCmuOCmguCmluCnjeCmr+CmviDgppMg4Kaa4Ka/4Ka54KeN4Kao4KeH4KawIOCmruCmv+CmtuCnjeCmsOCmozwvcD4KICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0icHdfZ28iPuCmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoSDgpqzgpqbgprLgpr7gpqg8L2J1dHRvbj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Kam4KeB4KaHLeCmp+CmvuCmqiDgpq/gpr7gpprgpr7gpocgKDJGQSk8L2gzPgogICA8cCBjbGFzcz0ibXV0ZWQiPuCmmuCmvuCmsuCngSDgpqXgpr7gppXgprLgp4cg4Kay4KaX4KaH4Kao4KeH4KawIOCmuOCmruCmr+CmvCDgpoXgpqXgp4fgpqjgpp/gpr/gppXgp4fgpp/gprAg4KaF4KeN4Kav4Ka+4Kaq4KeH4KawIChHb29nbGUgQXV0aGVudGljYXRvci9BdXRoeSkg4KaV4KeL4Kah4KaTIOCmsuCmvuCml+CmrOCnh+ClpDwvcD4KICAgPGRpdiBpZD0idGZhQm94Ij4ke01FLnRvdHBfb24/JzxkaXYgY2xhc3M9Im9rYmFubmVyIj7inJMgMkZBIOCmmuCmvuCmsuCngSDgpobgppvgp4c8L2Rpdj48YnV0dG9uIGNsYXNzPSJidG4gZGFuZ2VyIHNtIiBpZD0idGZhX29mZiI+4Kas4Kao4KeN4KanIOCmleCmsOCngeCmqDwvYnV0dG9uPic6JzxidXR0b24gY2xhc3M9ImJ0biBzbSIgaWQ9InRmYV9zZXR1cCI+4Kaa4Ka+4Kay4KeBIOCmleCmsOCngeCmqDwvYnV0dG9uPid9PC9kaXY+PC9kaXY+CiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgzPuCmuOCmleCnjeCmsOCmv+Cmr+CmvCDgprjgp4fgprbgpqg8L2gzPjxkaXYgaWQ9InNlc0JveCI+PGRpdiBjbGFzcz0ic3BpbiI+PC9kaXY+PC9kaXY+CiAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCBzbSIgaWQ9InNlc19yZXZva2UiIHN0eWxlPSJtYXJnaW4tdG9wOjEwcHgiPuCmheCmqOCnjeCmryDgprjgpqwg4Kah4Ka/4Kat4Ka+4KaH4Ka4IOCmpeCnh+CmleCnhyDgprLgppfgpobgpongpp88L2J1dHRvbj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJjYXJkIj48aDM+4Ka44Ka+4Kau4KeN4Kaq4KeN4Kaw4Kak4Ka/4KaVIOCmleCmvuCmsOCnjeCmr+CmleCnjeCmsOCmrjwvaDM+PGRpdiBpZD0iYXVkaXRCb3giPjxkaXYgY2xhc3M9InNwaW4iPjwvZGl2PjwvZGl2PjwvZGl2PmA7CiAkKCcjcHdfZ28nKS5vbmNsaWNrPWFzeW5jKCk9PnsKICBjb25zdCBjdXI9JCgnI3B3X2N1cicpLnZhbHVlLG53PSQoJyNwd19uZXcnKS52YWx1ZTsKICBjb25zdCBiPSQoJyNwd19nbycpO2IuZGlzYWJsZWQ9dHJ1ZTtiLnRleHRDb250ZW50PSfgprngpprgp43gppvgp4figKYnOwogIHRyeXthd2FpdCBhcGkoJy9hZG1pbi9hcGkvcGFzc3dvcmQnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2N1cnJlbnQ6Y3VyLG5ldzpud30pfSk7dG9hc3QoJ+CmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoSDgpqzgpqbgprLgpr7gpqjgp4sg4Ka54Kav4Ka84KeH4Kab4KeHJyk7JCgnI3B3X2N1cicpLnZhbHVlPSQoJyNwd19uZXcnKS52YWx1ZT0nJzt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KICBiLmRpc2FibGVkPWZhbHNlO2IudGV4dENvbnRlbnQ9J+CmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoSDgpqzgpqbgprLgpr7gpqgnOwogfTsKIGlmKCQoJyN0ZmFfc2V0dXAnKSkkKCcjdGZhX3NldHVwJykub25jbGljaz10ZmFTZXR1cDsKIGlmKCQoJyN0ZmFfb2ZmJykpJCgnI3RmYV9vZmYnKS5vbmNsaWNrPXRmYURpc2FibGU7CiBsb2FkU2Vzc2lvbnMoKTtsb2FkQXVkaXQoKTsKfSk7CmFzeW5jIGZ1bmN0aW9uIHRmYVNldHVwKCl7CiBjb25zdCBkPWF3YWl0IGFwaSgnL2FkbWluL2FwaS8yZmEvc2V0dXAnLHttZXRob2Q6J1BPU1QnfSk7CiBjb25zdCBvdHBVcmk9ZC51cmk7CiBjb25zdCBxclVybD0naHR0cHM6Ly9jaGFydC5nb29nbGVhcGlzLmNvbS9jaGFydD9jaHM9MjAweDIwMCZjaHQ9cXImY2hsPScrZW5jb2RlVVJJQ29tcG9uZW50KG90cFVyaSk7CiBvcGVuTW9kYWwoJzJGQSDgpprgpr7gprLgp4Eg4KaV4Kaw4KeB4KaoJywKICBgPHA+4KaF4Kal4KeH4Kao4Kaf4Ka/4KaV4KeH4Kaf4KawIOCmheCnjeCmr+CmvuCmqiDgpqbgpr/gpq/gprzgp4cg4Kao4Ka/4Kaa4KeH4KawIOCmleCni+CmoSDgprjgp43gppXgp43gpq/gpr7gpqgg4KaV4Kaw4KeB4KaoLCDgpoXgpqXgpqzgpr4g4KaX4KeL4Kaq4KaoIOCmleCni+CmoeCmn+CmvyDgpq7gp43gpq/gpr7gpqjgp4Hgpq/gprzgpr7gprLgpr8g4Kay4Ka/4KaW4KeB4KaoOjwvcD4KICAgPGRpdiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxpbWcgc3JjPSIke3FyVXJsfSIgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIHN0eWxlPSJib3JkZXItcmFkaXVzOjEwcHgiIG9uZXJyb3I9InRoaXMuc3R5bGUuZGlzcGxheT0nbm9uZSciPjwvZGl2PgogICA8cCBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIGNsYXNzPSJtb25vIj4ke2VzYyhkLnNlY3JldCl9PC9zcGFuPjwvcD4KICAgPGRpdiBjbGFzcz0iZiI+PHNwYW4+4KaF4KeN4Kav4Ka+4Kaq4KeHIOCmpuCnh+CmluCmvuCmqOCniyDgp6wg4Ka44KaC4KaW4KeN4Kav4Ka+4KawIOCmleCni+CmoSDgpqbgpr/gpqg8L3NwYW4+PGlucHV0IGlkPSJ0ZmFfY29kZSIgaW5wdXRtb2RlPSJudW1lcmljIiBtYXhsZW5ndGg9IjYiPjwvZGl2PmAsCiAgYDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9Im1DYW5jZWwiPuCmrOCmvuCmpOCmv+CmsjwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InRmYV9jb25maXJtIj7gpqjgpr/gprbgp43gpprgpr/gpqQg4KaV4Kaw4KeB4KaoPC9idXR0b24+YCk7CiAkKCcjbUNhbmNlbCcpLm9uY2xpY2s9Y2xvc2VNb2RhbDsKICQoJyN0ZmFfY29uZmlybScpLm9uY2xpY2s9YXN5bmMoKT0+ewogIHRyeXthd2FpdCBhcGkoJy9hZG1pbi9hcGkvMmZhL2VuYWJsZScse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7Y29kZTokKCcjdGZhX2NvZGUnKS52YWx1ZX0pfSk7dG9hc3QoJzJGQSDgpprgpr7gprLgp4Eg4Ka54Kav4Ka84KeH4Kab4KeHJyk7Y2xvc2VNb2RhbCgpO01FLnRvdHBfb249dHJ1ZTtyZW5kZXJSb3V0ZSgpO30KICBjYXRjaChlKXt0b2FzdChlLm1lc3NhZ2UsdHJ1ZSk7fQogfTsKfQpmdW5jdGlvbiB0ZmFEaXNhYmxlKCl7CiBvcGVuTW9kYWwoJzJGQSDgpqzgpqjgp43gpqcg4KaV4Kaw4KeB4KaoJywgYDxwPuCmqOCmv+CmtuCnjeCmmuCmv+CmpCDgprngpqTgp4cg4KaG4Kaq4Kao4Ka+4KawIOCmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoSDgpqbgpr/gpqg6PC9wPjxkaXYgY2xhc3M9ImYiPjxzcGFuPuCmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoTwvc3Bhbj48aW5wdXQgaWQ9InRmYV9wdyIgdHlwZT0icGFzc3dvcmQiPjwvZGl2PmAsCiAgYDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9Im1DYW5jZWwiPuCmrOCmvuCmpOCmv+CmsjwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biBkYW5nZXIiIGlkPSJ0ZmFfY29uZmlybTIiPuCmrOCmqOCnjeCmpyDgppXgprDgp4Hgpqg8L2J1dHRvbj5gKTsKICQoJyNtQ2FuY2VsJykub25jbGljaz1jbG9zZU1vZGFsOwogJCgnI3RmYV9jb25maXJtMicpLm9uY2xpY2s9YXN5bmMoKT0+ewogIHRyeXthd2FpdCBhcGkoJy9hZG1pbi9hcGkvMmZhL2Rpc2FibGUnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe3Bhc3N3b3JkOiQoJyN0ZmFfcHcnKS52YWx1ZX0pfSk7dG9hc3QoJzJGQSDgpqzgpqjgp43gpqcg4Ka54Kav4Ka84KeH4Kab4KeHJyk7Y2xvc2VNb2RhbCgpO01FLnRvdHBfb249ZmFsc2U7cmVuZGVyUm91dGUoKTt9CiAgY2F0Y2goZSl7dG9hc3QoZS5tZXNzYWdlLHRydWUpO30KIH07Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZFNlc3Npb25zKCl7CiBjb25zdCBkPWF3YWl0IGFwaSgnL2FkbWluL2FwaS9zZXNzaW9ucycpOwogJCgnI3Nlc0JveCcpLmlubmVySFRNTD1kLml0ZW1zLm1hcChzPT5gPGRpdiBjbGFzcz0ic2Vzcm93Ij48c3Bhbj4ke2VzYyhzLmlwKX0ke3MuY3VycmVudD8nIDxiPijgpo/gpocg4Kah4Ka/4Kat4Ka+4KaH4Ka4KTwvYj4nOicnfTxicj48c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTEuNXB4Ij4ke2VzYygocy51YXx8JycpLnNsaWNlKDAsNjApKX08L3NwYW4+PC9zcGFuPjxzcGFuIGNsYXNzPSJtdXRlZCI+JHtmbXREYXRlKHMubGFzdCl9PC9zcGFuPjwvZGl2PmApLmpvaW4oJycpOwogJCgnI3Nlc19yZXZva2UnKS5vbmNsaWNrPWFzeW5jKCk9Pnt0cnl7YXdhaXQgYXBpKCcvYWRtaW4vYXBpL3Nlc3Npb25zL3Jldm9rZScse21ldGhvZDonUE9TVCd9KTt0b2FzdCgn4KaF4Kao4KeN4KavIOCmuOCmrCDgprjgp4fgprbgpqgg4Kay4KaX4KaG4KaJ4KafIOCmueCmr+CmvOCnh+Cmm+CnhycpO2xvYWRTZXNzaW9ucygpO31jYXRjaChlKXt0b2FzdChlLm1lc3NhZ2UsdHJ1ZSk7fX07Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZEF1ZGl0KCl7CiBjb25zdCBkPWF3YWl0IGFwaSgnL2FkbWluL2FwaS9hdWRpdCcpOwogJCgnI2F1ZGl0Qm94JykuaW5uZXJIVE1MPWQuaXRlbXMubWFwKGE9PmA8ZGl2IGNsYXNzPSJhdWRpdHJvdyI+PHNwYW4+JHtlc2MoYS5hZG1pbil9IOKAlCAke2F1ZGl0Qm4oYS5hY3Rpb24pfSR7YS5kZXRhaWw/JzogJytlc2MoYS5kZXRhaWwpOicnfTwvc3Bhbj48c3BhbiBjbGFzcz0ibXV0ZWQiPiR7Zm10RGF0ZShhLmF0KX08L3NwYW4+PC9kaXY+YCkuam9pbignJyl8fCc8cCBjbGFzcz0ibXV0ZWQiPuCmleCmv+Cmm+CngSDgpqjgp4fgpoc8L3A+JzsKfQpmdW5jdGlvbiBhdWRpdEJuKGEpe3JldHVybiB7bG9naW46J+CmsuCml+Cmh+CmqCcsbG9nb3V0OifgprLgppfgpobgpongpp8nLGxvZ2luX2ZhaWxlZDon4Kat4KeB4KayIOCmsuCml+Cmh+CmqCDgpprgp4fgprfgp43gpp/gpr4nLHBhc3N3b3JkX2NoYW5nZWQ6J+CmquCmvuCmuOCmk+Cmr+CmvOCmvuCmsOCnjeCmoSDgpqzgpqbgprLgpr7gpqjgp4sg4Ka54Kav4Ka84KeH4Kab4KeHJywnMmZhX2VuYWJsZWQnOicyRkEg4Kaa4Ka+4Kay4KeBJywnMmZhX2Rpc2FibGVkJzonMkZBIOCmrOCmqOCnjeCmpycsc2Vzc2lvbnNfcmV2b2tlZDon4Ka44KeH4Ka24KaoIOCmsuCml+CmhuCmieCmnycsb3JkZXJfc3RhdHVzOifgpoXgprDgp43gpqHgpr7gprAg4KaF4Kas4Ka44KeN4Kal4Ka+JyxvcmRlcl9wYXk6J+CmquCnh+CmruCnh+CmqOCnjeCmnyDgpoXgpqzgprjgp43gpqXgpr4nLHByb2R1Y3RfYWRkOifgpqrgpqPgp43gpq8g4Kav4KeL4KaXJyxwcm9kdWN0X2VkaXQ6J+CmquCmo+CnjeCmryDgprjgpq7gp43gpqrgpr7gpqbgpqjgpr4nLHByb2R1Y3RfZGVsZXRlOifgpqrgpqPgp43gpq8g4Kau4KeL4Kab4Ka+Jyxwcm9kdWN0X2hpZGU6J+CmquCmo+CnjeCmryDgprLgp4HgppXgpr7gpqjgp4snLGNhdGVnb3J5X2FkZDon4KaV4KeN4Kav4Ka+4Kaf4Ka+4KaX4Kaw4Ka/IOCmr+Cni+CmlycsY2F0ZWdvcnlfZWRpdDon4KaV4KeN4Kav4Ka+4Kaf4Ka+4KaX4Kaw4Ka/IOCmuOCmruCnjeCmquCmvuCmpuCmqOCmvicsY2F0ZWdvcnlfZGVsZXRlOifgppXgp43gpq/gpr7gpp/gpr7gppfgprDgpr8g4Kau4KeL4Kab4Ka+Jyxjb3Vwb25fYWRkOifgppXgp4Hgpqrgpqgg4Kav4KeL4KaXJyxjb3Vwb25fZWRpdDon4KaV4KeB4Kaq4KaoIOCmuOCmruCnjeCmquCmvuCmpuCmqOCmvicsY291cG9uX2RlbGV0ZTon4KaV4KeB4Kaq4KaoIOCmruCni+Cmm+CmvicsYmFubmVyX2FkZDon4Kas4KeN4Kav4Ka+4Kao4Ka+4KawIOCmr+Cni+CmlycsYmFubmVyX2VkaXQ6J+CmrOCnjeCmr+CmvuCmqOCmvuCmsCDgprjgpq7gp43gpqrgpr7gpqbgpqjgpr4nLGJhbm5lcl9kZWxldGU6J+CmrOCnjeCmr+CmvuCmqOCmvuCmsCDgpq7gp4vgppvgpr4nLHNldHRpbmdzX3NhdmVkOifgprjgp4fgpp/gpr/gpoLgprgg4Ka44KaC4Kaw4KaV4KeN4Ka34KajJyxvcmRlcnNfZXhwb3J0OifgpoXgprDgp43gpqHgpr7gprAg4KaP4KaV4KeN4Ka44Kaq4KeL4Kaw4KeN4KafJ31bYV18fGE7fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOCmtuCngeCmsOCngQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KYXN5bmMgZnVuY3Rpb24gYm9vdCgpewogc2hlbGwoKTsKIHJlbmRlclJvdXRlKCk7Cn0KKGFzeW5jIGZ1bmN0aW9uIGluaXQoKXsKIHRyeXtjb25zdCBtZT1hd2FpdCBhcGkoJy9hZG1pbi9hcGkvbWUnKTtDU1JGPW1lLmNzcmY7TUU9e3VzZXJuYW1lOm1lLnVzZXJuYW1lLHRvdHBfb246bWUudG90cF9vbn07Ym9vdCgpO30KIGNhdGNoKGUpe3Nob3dMb2dpbigpO30KfSkoKTsK")

if __name__ == "__main__":
    main()
