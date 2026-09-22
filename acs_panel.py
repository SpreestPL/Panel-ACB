#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Uniwersalny panel do kontrolerów dostępu rodziny ACB ("Web Controller", TCP/IP).

Funkcje:
  * wyszukiwanie kontrolerów w sieci lokalnej (skan podsieci),
  * rozpoznawanie modelu (ACB-001 / ACB-002 / ACB-004) po liczbie drzwi,
  * pełna obsługa wykrytego kontrolera przez czysty interfejs WWW.

Model rozpoznawany jest po liczbie niezależnych drzwi/przekaźników:
  ACB-001 = 1 drzwi, ACB-002 = 2 drzwi, ACB-004 = 4 drzwi.
Protokół HTTP jest wspólny dla całej rodziny; wszystkie trzy modele są zweryfikowane
na sprzęcie (ACB-002 i ACB-004 także z fabrycznym chińskim interfejsem).
Każdy model obsługuje jedno zapytanie i jedno połączenie naraz (docs/PROTOCOL.md).

Uruchomienie:
    python3 acs_panel.py        (bez zewnętrznych bibliotek)
Panel:  http://127.0.0.1:8088

Zmienne środowiskowe (opcjonalnie):
    ACS_HOST  - IP z którym połączyć się od razu (prefill), np. 192.168.1.100
    ACS_USER / ACS_PWD - domyślne dane logowania (admin / admin)
    ACS_PORT  - port lokalnego panelu (8088)
    ACS_BIND  - adres nasłuchu panelu (127.0.0.1; 192.168.1.10 = dostęp z sieci LAN)
    ACS_DATA  - katalog danych (domyślnie: Windows %APPDATA%\\ACB Panel,
                macOS ~/Library/Application Support/ACB Panel, Linux ~/.local/share/acb-panel)
    ACS_SAVED - plik zapisanych kontrolerów (controllers.json w katalogu danych)
    ACS_DEVICE_LOG - dziennik komunikacji z kontrolerami (acb-device.log w katalogu danych)
    ACS_DB    - baza panelu: działy, pracownicy, kopia logu przejść (acb-panel.db w katalogu danych)
    ACS_UDP_PORT - port natywnego kanału UDP kontrolera (60000; godziny wejścia działów)
    ACS_ONLINE_POLL - co ile sekund sprawdzać, czy zapisane kontrolery są online (30)
    ACS_NO_BROWSER=1 - nie otwieraj przeglądarki po uruchomieniu
    ACS_TLS_CERT / ACS_TLS_KEY - certyfikat i klucz PEM: panel działa po HTTPS
    ACS_ADMIN_LOGIN / ACS_ADMIN_PASSWORD - pierwsze konto administratora panelu (gdy nie ma żadnego)
    ACS_AUTH=0 - bez logowania do panelu (tylko gdy panel słucha na 127.0.0.1)
    ACS_TRUST_PROXY=1 - panel stoi za serwerem pośredniczącym (np. Caddy): adres klienta z X-Forwarded-For
    ACS_SESSION_HOURS - po ilu godzinach bezczynności sesja wygasa (12)
    ACS_AUTOCONNECT_DELAY - po ilu sekundach od startu łączyć kontrolery z automatycznym łączeniem (65)
"""

import os
import re
import sys
import csv
import io
import time
import shutil
import sqlite3
import datetime
import itertools
import contextlib
import webbrowser
import json
import html
import socket
import select
import struct
import threading
import unicodedata
import ipaddress
import hashlib
import base64
import hmac
import secrets
import ssl
import smtplib
import collections
import urllib.request
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode
import http.client


APP_VERSION = "2.9.0"

# Tryb pracy panelu (ACS_MODE):
#   online  - panel jest stale połączony z kontrolerem i pracuje w tle: przełącza PIN-y kart przy kilku
#             zmianach (entry_pins_sync / _watch_loop), czyta zdarzenia na żywo, pilnuje otwartych drzwi
#             i wysyła powiadomienia. Tak działa panel na serwerze albo na komputerze włączonym całą dobę.
#   offline - panel uruchamiany doraźnie (np. raz w miesiącu po wyciąg czasu pracy). Łączy się z zapisanym
#             kontrolerem po starcie, trzyma połączenie przez całą sesję i po połączeniu dociąga log przejść,
#             ale nie uruchamia zadań wymagających CIĄGŁEJ pracy panelu - te funkcje są wyłączone
#             (OFFLINE_OFF) i ukryte w interfejsie, żeby nikt nie liczył na ochronę, której nie ma.
PANEL_MODE = (os.environ.get("ACS_MODE", "online").strip().lower() or "online")
if PANEL_MODE not in ("online", "offline"):
    PANEL_MODE = "online"
OFFLINE = PANEL_MODE == "offline"
MODE_NAMES = {"online": "online", "offline": "offline"}
# funkcje niedostępne w trybie offline: nazwa -> dlaczego (tekst trafia do interfejsu i do błędów API)
OFFLINE_OFF = {
    "live": "podgląd zdarzeń na żywo",
    "notify": "powiadomienia (e-mail, Telegram, webhook)",
    "doors": "ostrzeżenie o drzwiach otwartych zbyt długo",
    "shifts": "godziny wejścia w kilku zmianach (różne godziny dla różnych działów)",
}
OFFLINE_WHY = ("Ta funkcja wymaga panelu połączonego z kontrolerem bez przerwy - w trybie offline panel "
               "działa tylko wtedy, gdy jest uruchomiony, więc nie może jej pilnować. Użyj trybu online.")

DEF_HOST = os.environ.get("ACS_HOST", "")
DEF_USER = os.environ.get("ACS_USER", "admin")
DEF_PWD = os.environ.get("ACS_PWD", "admin")
LISTEN_PORT = int(os.environ.get("ACS_PORT", "8088"))
LISTEN_HOST = os.environ.get("ACS_BIND", "127.0.0.1")   # np. 192.168.1.10 = dostęp z LAN
OPEN_BROWSER = os.environ.get("ACS_NO_BROWSER", "") in ("", "0")
TLS_CERT = os.environ.get("ACS_TLS_CERT", "")
TLS_KEY = os.environ.get("ACS_TLS_KEY", "")
TRUST_PROXY = os.environ.get("ACS_TRUST_PROXY", "") == "1"
SESSION_IDLE = float(os.environ.get("ACS_SESSION_HOURS", "12")) * 3600
SESSION_MAX = 7 * 24 * 3600
# w trybie offline panel łączy się od razu po starcie - nie wisiał wcześniej na kontrolerze,
# więc nie trzeba czekać, aż kontroler zwolni poprzednie połączenie TCP (docs/PROTOCOL.md)
AUTOCONNECT_DELAY = float(os.environ.get("ACS_AUTOCONNECT_DELAY", "0" if OFFLINE else "65"))


def _data_dir():
    """Katalog danych użytkownika - program może leżeć w folderze tylko do odczytu
    (np. rozpakowany z archiwum), więc zapisane kontrolery i dziennik trzymamy osobno."""
    if os.environ.get("ACS_DATA"):
        return os.environ["ACS_DATA"]
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ACB Panel")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/ACB Panel")
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
                        "acb-panel")


DATA_DIR = _data_dir()
SAVED_FILE = os.environ.get("ACS_SAVED", os.path.join(DATA_DIR, "controllers.json"))
# wcześniejsze wersje trzymały listę obok programu - przenieś ją przy pierwszym uruchomieniu
_LEGACY_SAVED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "controllers.json")
if "ACS_SAVED" not in os.environ and not os.path.exists(SAVED_FILE) and os.path.exists(_LEGACY_SAVED):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        shutil.copy2(_LEGACY_SAVED, SAVED_FILE)
    except OSError:
        SAVED_FILE = _LEGACY_SAVED
# kontroler z chińskim interfejsem przełączany na angielski przy połączeniu (0 = zostaw język)
FORCE_ENGLISH = os.environ.get("ACS_FORCE_ENGLISH", "1") != "0"
TIMEOUT = 12
AUTOADD_TIMEOUT = 60     # po ilu sekundach tryb auto-dodawania wyłącza się sam

# --- rejestr modeli ----------------------------------------------------------
# doors  = liczba niezależnych drzwi/przekaźników (sygnatura modelu)
# verified = czy profil został potwierdzony na fizycznym sprzęcie
# inout  = przy każdych drzwiach czytnik wejścia i wyjścia. Bez tego (ACB-004) czas pracy liczy się z PAR drzwi:
#          administrator wskazuje w zakładce „Drzwi”, które drzwi są wejściem, a które wyjściem (door_tracking.role)
MODELS = {
    1: {"name": "ACB-001", "doors": 1, "verified": True, "inout": True,
        "readers": "2 czytniki: wejście + wyjście"},
    2: {"name": "ACB-002", "doors": 2, "verified": True, "inout": True,
        "readers": "4 czytniki: wejście + wyjście na drzwi"},
    # ACB-004: 4 przekaźniki na 4 drzwi, log podaje tylko wejście (IN) - wyjście = odbicie na drzwiach „wyjścia”
    4: {"name": "ACB-004", "doors": 4, "verified": True, "inout": False, "readers": ""},
}

# Interfejs urządzenia bywa po angielsku albo po chińsku (ustawienie [Language]).
# Nazwy pól i przycisków (ACT_ID_*, E<xx>, S<xx>, PWD<n>...) są w obu wersjach te same,
# różnią się tylko teksty - panel opiera się na nazwach pól, a teksty rozpoznaje w obu językach.
# ACB-002 (nr 200000002, V6.62.51215) pracuje fabrycznie po chińsku.
LOGIN_MARKERS = ("Web Controller", "网络门禁")
ZH_TEXT = [                     # tłumaczenie wartości wyświetlanych przez chiński interfejs
    ("远程开门", "Remote Open"), ("禁止", "Denied"), ("允许", "Allowed"),
    ("进门", "IN"), ("出门", "OUT"), ("号门", " Door"),
    ("未启用", "Disabled"), ("不启用", "Disabled"), ("启用", "Enabled"),
    ("中文", "Chinese"), ("英文", "English"), ("开", "Open"), ("关", "Closed"),
]


def zh_to_en(s):
    for zh, en in ZH_TEXT:
        s = s.replace(zh, en)
    return re.sub(r"\s+", " ", s).strip()


# Ten sam wpis logu przejść w obu językach (ACB-002, V6.62.51215):
#   EN "Forbid IN[#1DOOR]"           ZH "禁止 进门[#1号门]"   -> "Denied IN[#1 Door]"
#   EN "Remote Open Door IN[#2DOOR]" ZH "远程开门 进门[#2号门]" -> "Remote Open IN[#2 Door]"
EN_STATUS = [(r"\bForbid\b", "Denied"), (r"\bRemote Open Door\b", "Remote Open"),
             (r"#(\d+)\s*DOOR\b", r"#\1 Door")]


def swipe_status(s):
    s = zh_to_en(s)
    for pat, rep in EN_STATUS:
        s = re.sub(pat, rep, s, flags=re.I)
    return s


def model_for_doors(doors):
    m = MODELS.get(doors)
    if m:
        return dict(m)
    return {"name": f"ACB-? ({doors} drzwi)", "doors": doors, "verified": False}


class ControllerError(Exception):
    pass


class DeviceError(ControllerError):
    """Błąd komunikacji z urządzeniem (brak odpowiedzi, zerwane połączenie)."""


# --- dostęp do urządzeń: jedno zapytanie naraz, JEDNO połączenie TCP ----------
# Ustalone doświadczalnie (ACB-001, V6.62): stos TCP kontrolera nie zwalnia miejsca
# po zamkniętym połączeniu - obsługuje tylko 11 połączeń od uruchomienia, a 12.
# zawiesza urządzenie i watchdog je restartuje ("Reboot" w logu). Przeglądarka
# używa jednego połączenia keep-alive, więc problem był niewidoczny; panel tworzył
# nowe połączenie przy każdej operacji. Dlatego:
#   * dla każdego IP jest jedna bramka z JEDNYM trwałym połączeniem HTTP/1.1,
#     nowe połączenie powstaje tylko, gdy urządzenie zamknie poprzednie / po restarcie,
#   * wspólna blokada na IP (RLock - wieloetapowe sekwencje trzymają ją w całości),
#   * minimalny odstęp między zapytaniami (REQUEST_GAP).
REQUEST_GAP = 0.15
# dziennik komunikacji z urządzeniami (diagnostyka restartów): tylko NAZWY pól, bez wartości
DEVICE_LOG = os.environ.get("ACS_DEVICE_LOG", os.path.join(DATA_DIR, "acb-device.log"))
DEVICE_LOG_MAX = 5 * 1024 * 1024      # powyżej - dziennik przenoszony do .1 (jedna kopia)
_DEVLOG_LOCK = threading.Lock()


def _devlog(line):
    if not DEVICE_LOG:
        return
    try:
        with _DEVLOG_LOCK:
            os.makedirs(os.path.dirname(DEVICE_LOG) or ".", exist_ok=True)
            if os.path.exists(DEVICE_LOG) and os.path.getsize(DEVICE_LOG) > DEVICE_LOG_MAX:
                os.replace(DEVICE_LOG, DEVICE_LOG + ".1")
        with _DEVLOG_LOCK, open(DEVICE_LOG, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + ("%.3f" % (time.time() % 1))[1:] + " " + line + "\n")
    except OSError:
        pass




class DeviceResponse:
    def __init__(self, status, content):
        self.status_code = status
        self.content = content
        self.text = content.decode("utf-8", "replace")


class _GateConnection(http.client.HTTPConnection):
    def __init__(self, gate, host, port):
        super().__init__(host, port)
        self.gate = gate

    def connect(self):
        super().connect()
        self.gate.connections += 1
        _devlog(f"CONNECT {self.gate.host} nowe połączenie TCP #{self.gate.connections}")


class DeviceGate:
    def __init__(self, host):
        self.host = str(host)
        name, _, port = self.host.partition(":")
        self.lock = threading.RLock()
        self.last = 0.0
        self.connections = 0          # ile połączeń TCP otworzył ten proces
        self.conn = _GateConnection(self, name, int(port or 80))

    def close(self):
        with self.lock:
            self.conn.close()

    @property
    def connected(self):
        return self.conn.sock is not None

    def request(self, method, url, session=None, timeout=TIMEOUT, data=None, connect_timeout=None):
        """Zapytanie przez trwałe połączenie. `session` - pozostawione dla zgodności, nieużywane."""
        u = urlparse(url)
        path = u.path or "/"
        body = urlencode(data) if data is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
        pairs = list(data.items()) if isinstance(data, dict) else list(data or [])
        what = f"{method} {self.host}{path} {','.join(k for k, _ in pairs)}"
        with self.lock:
            wait = self.last + REQUEST_GAP - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            t0 = time.monotonic()
            try:
                for attempt in (1, 2):
                    reused = self.connected
                    try:
                        if not reused:
                            self.conn.timeout = connect_timeout or timeout
                            self.conn.connect()
                        self.conn.sock.settimeout(timeout)
                        self.conn.request(method, path, body=body, headers=headers)
                        resp = self.conn.getresponse()
                        content = resp.read()
                        if resp.will_close:
                            self.conn.close()
                        break
                    except (http.client.RemoteDisconnected, BrokenPipeError,
                            ConnectionResetError, ConnectionAbortedError):
                        # urządzenie zamknęło połączenie (np. po restarcie) - jedno ponowienie
                        self.conn.close()
                        if reused and attempt == 1:
                            continue
                        raise
                    except BaseException:
                        self.conn.close()
                        raise
            except (OSError, http.client.HTTPException) as e:
                _devlog(f"{what} ERR {type(e).__name__} {time.monotonic() - t0:.2f}s")
                raise DeviceError(f"Brak odpowiedzi kontrolera {self.host} ({type(e).__name__})") from e
            finally:
                self.last = time.monotonic()
            _devlog(f"{what} {resp.status} {len(content)}B {time.monotonic() - t0:.2f}s")
            return DeviceResponse(resp.status, content)


_GATES = {}
_GATES_LOCK = threading.Lock()


def gate(host):
    with _GATES_LOCK:
        g = _GATES.get(str(host))
        if g is None:
            g = _GATES[str(host)] = DeviceGate(host)
        return g


# --- natywny kanał UDP 60000 (protokół WG) -----------------------------------
# Kontrolery ACB to sprzęt WG (Weigeng). Strona WWW nie ma harmonogramów - lista zadań kontrolera
# jest dostępna tylko przez 64-bajtowe pakiety UDP (docs/PROTOCOL.md, „Kanał UDP 60000”):
# [0]=0x17, [1]=funkcja, [4..7]=nr urządzenia (LE), [8..39]=dane, [40..43]=nr kolejny.
# UDP nie zużywa limitu połączeń TCP, ale zapytania i tak idą pod blokadą bramki kontrolera.
WG_PORT = int(os.environ.get("ACS_UDP_PORT", "60000"))
WG_MAGIC = bytes([0x55, 0xAA, 0xAA, 0x55])
_WG_SEQ = itertools.count(1)


class WgUdp:
    def __init__(self, host, serial):
        self.addr = (str(host).partition(":")[0], WG_PORT)
        self.serial = int(serial)

    def request(self, func, data=b"", quiet=False, tries=3, log_errors=True):
        pkt = bytearray(64)
        pkt[0], pkt[1] = 0x17, func
        struct.pack_into("<I", pkt, 4, self.serial)
        pkt[8:8 + len(data)] = data
        struct.pack_into("<I", pkt, 40, next(_WG_SEQ) & 0x7FFFFFFF)
        t0 = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.5)
            for attempt in range(tries):
                sock.sendto(bytes(pkt), self.addr)
                try:
                    while True:
                        d, _ = sock.recvfrom(1024)
                        if (len(d) >= 40 and d[0] == 0x17 and d[1] == func
                                and struct.unpack_from("<I", d, 4)[0] == self.serial):
                            if not quiet:       # odpytywanie stanu co 0,5 s zalałoby dziennik
                                _devlog(f"UDP {self.addr[0]} 0x{func:02X} ok {time.monotonic() - t0:.2f}s")
                            return d[8:40]
                except socket.timeout:
                    continue
                except OSError as e:
                    if log_errors:
                        _devlog(f"UDP {self.addr[0]} 0x{func:02X} ERR {type(e).__name__}")
                    raise DeviceError(f"Brak odpowiedzi kontrolera {self.addr[0]} na porcie UDP {WG_PORT} "
                                      f"({type(e).__name__})") from e
        if log_errors:
            _devlog(f"UDP {self.addr[0]} 0x{func:02X} ERR timeout")
        raise DeviceError(f"Kontroler {self.addr[0]} nie odpowiada na porcie UDP {WG_PORT}")

    def ok(self, func, data, what):
        if self.request(func, data)[0] != 1:
            raise ControllerError(f"Kontroler odrzucił operację: {what}")

    def clock(self, quiet=False):
        try:
            return datetime.datetime.strptime(self.request(0x32, quiet=quiet)[:7].hex(), "%Y%m%d%H%M%S")
        except ValueError:
            raise ControllerError("Nie udało się odczytać zegara kontrolera")

    def last_event(self):
        """Ostatnie zdarzenie z odpowiedzi stanu 0x20 (nr rekordu = liczba rekordów w logu)."""
        return wg_event(self.request(0x20, quiet=True))

    def event(self, index):
        return wg_event(self.request(0xB0, struct.pack("<I", index), quiet=True))

    def privileges(self):
        """Wszystkie uprawnienia kart (0x58 liczba, 0x5C po kolei). Usunięte sloty (karta 0xFFFFFFFF)
        nie wchodzą do liczby, więc indeksy idą dalej niż liczba - do zliczenia wszystkich albo zera."""
        count = struct.unpack_from("<I", self.request(0x58, quiet=True), 0)[0]
        out, i = [], 0
        while len(out) < count and i < 100000:
            i += 1
            d = self.request(0x5C, struct.pack("<I", i), quiet=True)
            card = struct.unpack_from("<I", d, 0)[0]
            if card == 0:
                break
            if card != 0xFFFFFFFF:
                out.append(bytes(d[:19]))
        return out

    def set_pin(self, priv, pin):
        """Zapis uprawnienia (0x50) z nowym PIN-em - karta, daty i drzwi z odczytu bez zmian."""
        card = struct.unpack_from("<I", priv, 0)[0]
        self.ok(0x50, bytes(priv[:16]) + int(pin).to_bytes(3, "little"), f"zapis PIN-u karty {card}")
        d = self.request(0x5A, struct.pack("<I", card), quiet=True)
        if struct.unpack_from("<I", d, 0)[0] != card or int.from_bytes(d[16:19], "little") != int(pin):
            raise ControllerError(f"Kontroler nie zapisał PIN-u karty {card}")

    def card_doors(self, card):
        """Bajty dostępu do drzwi 1..4 z uprawnienia karty (0x5A); karta nieznana = same zera."""
        d = self.request(0x5A, struct.pack("<I", int(card)), quiet=True)
        return list(d[12:16]) if struct.unpack_from("<I", d, 0)[0] == int(card) else [0, 0, 0, 0]

    def open_door(self, door):
        self.ok(0x40, bytes([door]), f"zdalne otwarcie drzwi #{door}")

    def privilege(self, card):
        """Uprawnienie karty (0x5A) jako słownik priv_parse albo None, gdy karty nie ma w kontrolerze."""
        d = self.request(0x5A, struct.pack("<I", int(card)), quiet=True)
        return priv_parse(d) if struct.unpack_from("<I", d, 0)[0] == int(card) else None

    def write_privilege(self, p):
        """Zapis uprawnienia (0x50) i sprawdzenie odczytem 0x5A: karta, daty, drzwi i PIN."""
        self.ok(0x50, priv_build(p), f"zapis uprawnienia karty {p['card']}")
        after = self.privilege(p["card"])
        if after is None or {k: after[k] for k in PRIV_KEYS} != {k: p[k] for k in PRIV_KEYS}:
            raise ControllerError(f"Kontroler nie zapisał uprawnienia karty {p['card']}")
        return after


# Uprawnienie karty w protokole WG (19 bajtów): [0..3] karta, [4..7] ważna od YYYYMMDD (BCD),
# [8..11] ważna do, [12..15] drzwi 1..4 (0 zakaz, 1 zawsze, 2..254 strefa), [16..18] PIN.
PRIV_KEYS = ("card", "from", "to", "doors", "pin")
VALID_DEFAULT_TO = datetime.date(2029, 12, 31)   # ważność kart dodanych stroną WWW kontrolera


def priv_parse(d):
    def day(b):
        try:
            return datetime.datetime.strptime(bytes(b).hex(), "%Y%m%d").date()
        except ValueError:
            return None
    return {"card": str(struct.unpack_from("<I", d, 0)[0]), "from": day(d[4:8]), "to": day(d[8:12]),
            "doors": list(d[12:16]), "pin": int.from_bytes(bytes(d[16:19]), "little")}


def priv_build(p):
    return (struct.pack("<I", int(p["card"])) + _bcd_date(p["from"] or datetime.date(2011, 1, 1))
            + _bcd_date(p["to"] or VALID_DEFAULT_TO) + bytes(p["doors"][:4]) + int(p["pin"]).to_bytes(3, "little"))


WG_EVENT_SWIPE = 1          # typ zdarzenia: odbicie karty (2 = drzwi/przycisk, 3 = alarm)
WG_DIR_IN = 1               # kierunek: 1 = czytnik wejścia, 2 = wyjścia
# Kody powodu zdarzeń WG - według symulatora uhppoted (ten sam protokół). Na sprzęcie ACB sprawdzone:
# 1, 6, 7, 15, 20, 23, 24, 25, 44; pozostałe opisy są z dokumentacji WG i mogą się różnić.
# Kod 15 dostaje na tym sprzęcie także karta po dacie „ważna do” (test 2026-09-17, ACB-002: kod 15
# na wejściu i na wyjściu) i przed datą „ważna od” (test 2026-09-22, ACB-004) - kodu 13 firmware nie używa. Blokada karty (drzwi = 0)
# daje kod 6. Zdarzeń typu 3 (alarmy) ten firmware nie zapisuje - patrz WG_ALARM_REASONS.
WG_REASONS = {
    1: "przyjęta", 5: "sterowanie z komputera", 6: "brak uprawnienia do drzwi", 7: "brak lub zły PIN",
    8: "anti-passback", 9: "wymagane kilka kart", 10: "pierwsza karta", 11: "drzwi zamknięte na stałe",
    12: "blokada śluzy", 13: "karta poza okresem ważności", 15: "poza strefą czasową lub okresem ważności",
    18: "nieznana karta", 20: "przycisk wyjścia", 23: "drzwi otwarte", 24: "drzwi zamknięte",
    25: "otwarcie hasłem", 28: "włączenie zasilania", 29: "restart kontrolera", 30: "przycisk wyłączony",
    33: "przycisk: blokada śluzy", 37: "drzwi otwarte zbyt długo", 38: "wymuszone otwarcie drzwi",
    39: "alarm pożarowy", 40: "wymuszone zamknięcie", 41: "alarm antykradzieżowy", 43: "wezwanie pomocy",
    44: "otwarcie z komputera", 45: "otwarcie z komputera",
}
# Alarmy (zdarzenia typu 3 albo te kody). Na ACB-002 nie udało się żadnego wywołać (test 2026-09-17:
# rozwarty czujnik drzwi bez karty i drzwi otwarte ponad 3,5 min dały tylko kody 23/24 w typie 2).
WG_ALARM_REASONS = {37, 38, 39, 40, 41, 43}
WG_REASON_UNKNOWN_CARD = 18
WG_EVENT_DOOR = 2           # typ zdarzenia drzwi/przycisku
WG_REASON_DOOR_OPEN = 23
WG_REASON_DOOR_CLOSED = 24


def wg_event(d):
    """Rekord zdarzenia z 0x20 / 0xB0: [0..3] nr, [4] typ, [5] przyjęte, [6] drzwi, [7] kierunek,
    [8..11] karta, [12..18] czas BCD, [19] kod powodu."""
    try:
        t = datetime.datetime.strptime(d[12:19].hex(), "%Y%m%d%H%M%S")
    except ValueError:
        t = None                    # pusty log (same zera)
    return {"record": struct.unpack_from("<I", d, 0)[0], "type": d[4], "granted": d[5] == 1,
            "door": d[6], "dir": d[7], "card": str(struct.unpack_from("<I", d, 8)[0]),
            "time": t, "reason": d[19]}


# --- godziny wejścia działów --------------------------------------------------
# Strefa czasowa karty blokuje oba czytniki drzwi (test 2026-09-16: wyjście po godzinach odrzucone
# kodem 15), więc strefami nie da się zrobić „wejście w godzinach działu, wyjście zawsze”.
# Lista zadań kontrolera działa per drzwi: tryb „karta + PIN na wejściu” (6) - czytnik wejścia bez
# klawiatury nie przekaże PIN-u, odmowa kodem 7, wyjście działa - oraz „karta bez PIN-u” (5).
# Sprawdzone na ACB-002; zadanie działa od razu po 0xAC. Karta z PIN-em 0 wchodzi także w trybie 6.
# Plan zapisu (entry_plan) zależy od grup, które mają karty w kontrolerze:
#   jedna zmiana (single) - wszystkie takie grupy mają te same godziny albo wejście o każdej porze:
#     tryb drzwi przełącza sama lista zadań (5 w godzinach, 6 poza nimi), PIN 0 mają na stałe tylko
#     grupy „o każdej porze” - działa bez panelu;
#   kilka zmian (multi) - różne godziny albo grupa z kartami bez wejścia: drzwi stale w trybie 6,
#     a w oknie grupy jej karty mają PIN 0, poza nim 345678 (entry_pins_sync) - tylko przy
#     włączonym i połączonym panelu; bez niego karty zostają w ostatnim stanie.
TASK_CARD_NO_PIN, TASK_CARD_IN_PIN = 5, 6
# Pojemność listy zadań kontrolera - sprzęt 2026-09-17 (ACB-002, V6.62): 204 zadania przyjęte,
# 205. odrzucone (0xA8 odpowiada 0). Zapis czyści listę (0xA6) przed dopisaniem, więc odrzucone
# zadanie zostawiłoby kontroler z niepełnym harmonogramem - liczbę sprawdzamy PRZED czyszczeniem.
WG_TASKS_MAX = 204
WEEKDAYS = ("pn", "wt", "śr", "cz", "pt", "so", "nd")
NODEPT = "nodept"               # grupa pracowników bez działu
GROUP_MODES = ("hours", "always", "none")
GROUP_DEFAULT = {"mode": "none", "start": "08:00", "end": "16:00", "days": "1111100"}


def _hhmm(v):
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", (v or "").strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ControllerError(f"Nieprawidłowa godzina: {v}")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


HOLIDAY_MODES = ("closed", "hours")
HOLIDAYS_MAX = 60


def _iso_day(v, what="data"):
    try:
        return datetime.date.fromisoformat(str(v or "").strip())
    except ValueError:
        raise ControllerError(f"Nieprawidłowa {what}: {v}")


def holidays_normalize(raw):
    """Wyjątki w kalendarzu: [{from, to, name, mode: closed|hours, start, end}] posortowane po dacie.
    closed - działy „w godzinach” nie wchodzą; hours - wchodzą tylko w podanych godzinach (dotyczy wszystkich
    takich działów). Działy „o każdej porze” i „brak wejścia” wyjątki pomijają."""
    out = []
    for h in raw if isinstance(raw, list) else []:
        if not isinstance(h, dict):
            continue
        d_from = _iso_day(h.get("from"), "data wyjątku")
        d_to = _iso_day(h.get("to") or h.get("from"), "data wyjątku")
        if d_to < d_from:
            raise ControllerError(f"Wyjątek {d_from}: data „do” jest wcześniejsza niż „od”")
        if (d_to - d_from).days > 366:
            raise ControllerError(f"Wyjątek {d_from}: najwyżej rok")
        mode = h.get("mode", "closed")
        if mode not in HOLIDAY_MODES:
            raise ControllerError(f"Nieprawidłowy rodzaj wyjątku: {mode}")
        out.append({"from": d_from.isoformat(), "to": d_to.isoformat(), "name": str(h.get("name") or "").strip()[:40],
                    "mode": mode, "start": _hhmm(h.get("start") or "08:00"), "end": _hhmm(h.get("end") or "12:00")})
    if len(out) > HOLIDAYS_MAX:
        raise ControllerError(f"Najwyżej {HOLIDAYS_MAX} wyjątków w kalendarzu")
    return sorted(out, key=lambda h: (h["from"], h["to"]))


def entry_hours_normalize(cfg, doors, dept_ids):
    """{"doors": {nr: bool}, "groups": {id_działu|nodept: {mode, start, end, days}}, "holidays": [...]} -> postać
    kanoniczna z walidacją. Działy spoza `dept_ids` (usunięte) wypadają, brakujące dostają
    GROUP_DEFAULT (brak wejścia). Godzina „do” wcześniejsza lub równa „od” = okno przez północ."""
    cfg = cfg if isinstance(cfg, dict) else {}
    raw_doors, raw_groups = cfg.get("doors") or {}, cfg.get("groups") or {}
    out = {"doors": {str(n): bool(raw_doors.get(str(n))) for n in range(1, doors + 1)}, "groups": {},
           "holidays": holidays_normalize(cfg.get("holidays"))}
    for key in [str(d) for d in dept_ids] + [NODEPT]:
        e = raw_groups.get(key) or {}
        item = {"mode": e.get("mode", GROUP_DEFAULT["mode"]),
                "start": _hhmm(e.get("start", GROUP_DEFAULT["start"])),
                "end": _hhmm(e.get("end", GROUP_DEFAULT["end"])),
                "days": str(e.get("days", GROUP_DEFAULT["days"]))}
        if item["mode"] not in GROUP_MODES:
            raise ControllerError(f"Nieprawidłowy tryb wejścia: {item['mode']}")
        if not re.fullmatch(r"[01]{7}", item["days"]):
            raise ControllerError("Nieprawidłowe dni tygodnia")
        if item["mode"] == "hours" and "1" not in item["days"]:
            raise ControllerError("Zaznacz dni tygodnia z wejściem (albo wybierz „brak wejścia”)")
        out["groups"][key] = item
    return out


def holiday_on(holidays, day):
    ds = day.isoformat()
    return next((h for h in holidays or () if h["from"] <= ds <= h["to"]), None)


def _window_on(item, day, holidays):
    """Okno wejścia grupy „w godzinach” zaczynające się w dniu `day`: (od, do) albo None."""
    h = holiday_on(holidays, day)
    if h:
        return (h["start"], h["end"]) if h["mode"] == "hours" else None
    return (item["start"], item["end"]) if item["days"][day.weekday()] == "1" else None


def group_allows(item, now, holidays=None):
    """Czy grupa może wejść w chwili `now` (czas kontrolera). Okno zaczyna się w zaznaczony dzień;
    okno przez północ (22:00–06:00) trwa do godziny „do” następnego dnia; „od” = „do” - cała doba.
    Wyjątek w kalendarzu zastępuje okno dnia, w którym się zaczyna."""
    if item["mode"] != "hours":
        return item["mode"] == "always"
    hm, today = now.strftime("%H:%M"), now.date()
    w = _window_on(item, today, holidays)
    if w and hm >= w[0] and (hm < w[1] or w[0] >= w[1]):
        return True
    w = _window_on(item, today - datetime.timedelta(days=1), holidays)
    return bool(w and w[0] >= w[1] and hm < w[1])


def groups_allowed(cfg, now):
    return frozenset(k for k, it in cfg["groups"].items() if group_allows(it, now, cfg.get("holidays")))


PLAN_OFF, PLAN_MULTI = {"kind": "off"}, {"kind": "multi"}


def entry_plan(cfg, present):
    """Plan dla konfiguracji i grup mających karty w kontrolerze (`present`); grupy bez kart się nie liczą.
    {"kind": "off"} | {"kind": "multi"} | {"kind": "single", "window": {start, end, days} | None}."""
    if not any(cfg["doors"].values()):
        return PLAN_OFF
    windows = set()
    for key, it in cfg["groups"].items():
        if key not in present or it["mode"] == "always":
            continue
        if it["mode"] == "none":
            return PLAN_MULTI
        windows.add((it["start"], it["end"], it["days"]))
    if len(windows) > 1:
        return PLAN_MULTI
    return {"kind": "single", "window": dict(zip(("start", "end", "days"), windows.pop())) if windows else None}


def free_groups(cfg, plan, now):
    """Grupy, których karty mają mieć teraz PIN 0. Przy jednej zmianie tylko „o każdej porze” -
    godziny zmiany przełącza kontroler, a PIN 0 zostawiony po godzinach wpuszczałby bez panelu."""
    if plan.get("kind") == "single":
        return frozenset(k for k, it in cfg["groups"].items() if it["mode"] == "always")
    return groups_allowed(cfg, now)


def _date_runs(days):
    """Posortowane daty -> [(pierwsza, ostatnia)] ciągów kolejnych dni."""
    runs = []
    for d in days:
        if runs and d == runs[-1][1] + datetime.timedelta(days=1):
            runs[-1][1] = d
        else:
            runs.append([d, d])
    return [tuple(r) for r in runs]


def entry_hours_tasks(cfg, plan, now):
    """Lista zadań kontrolera. Kilka zmian: drzwi z ograniczeniem w trybie 6 codziennie o 00:00 (odnawia
    tryb, gdyby kontroler go zgubił). Jedna zmiana: o 00:00, „od” i „do” tryb wynikający z godzin w danym
    dniu tygodnia (5 albo 6; obejmuje okna przez północ). Dni z wyjątkami w kalendarzu i dni po nich (okno
    przez północ) dostają zadania na konkretną datę, a zadania tygodniowe mają zakresy dat z pominięciem tych
    dni - kolejność zadań o tej samej minucie nie ma wtedy znaczenia. Do tego zadanie „na teraz” (tylko
    dzisiaj, bieżąca minuta) ustawiające tryb od razu - także 5 drzwiom bez ograniczeń, bo poprzednio
    zapisany tryb PIN zostaje w kontrolerze."""
    today, forever = now.date(), datetime.date(2099, 12, 31)
    one = datetime.timedelta(days=1)
    monday = datetime.datetime.combine(today - datetime.timedelta(days=today.weekday()), datetime.time())
    window = plan.get("window") if plan.get("kind") == "single" else None
    item = dict(window, mode="hours") if window else None
    holidays = cfg.get("holidays") or []
    special = set()
    for h in holidays:
        d, last = datetime.date.fromisoformat(h["from"]), datetime.date.fromisoformat(h["to"])
        while d <= last:
            special.update(x for x in (d, d + one) if today <= x <= forever)
            d += one
    special = sorted(special)
    # zakresy dat zadań tygodniowych: od dziś do 2099 bez dni specjalnych
    segments, start = [], today
    for a, b in _date_runs(special):
        if a > start:
            segments.append((start, a - one))
        start = b + one
    if start <= forever:
        segments.append((start, forever))
    times = sorted({"00:00"} | ({item["start"], item["end"]} if item else set())
                   | {t for h in holidays if h["mode"] == "hours" for t in (h["start"], h["end"])})
    tasks = []
    for door, on in sorted(cfg["doors"].items(), key=lambda x: int(x[0])):
        door = int(door)

        def add(task, hhmm, days, date_from=today, date_to=forever):
            tasks.append({"door": door, "task": task, "start": hhmm, "days": days, "from": date_from, "to": date_to})
        if not on or plan["kind"] == "off" or (plan["kind"] == "single" and not item):
            add(TASK_CARD_NO_PIN, now.strftime("%H:%M"), "1111111", today, today)
        elif plan["kind"] == "multi":
            add(TASK_CARD_IN_PIN, "00:00", "1111111")
            add(TASK_CARD_IN_PIN, now.strftime("%H:%M"), "1111111", today, today)
        else:
            for seg_from, seg_to in segments:
                for hhmm in sorted({"00:00", item["start"], item["end"]}):
                    h, m = map(int, hhmm.split(":"))
                    open_days = "".join("1" if group_allows(item, monday + datetime.timedelta(days=i, hours=h, minutes=m))
                                        else "0" for i in range(7))
                    if "1" in open_days:
                        add(TASK_CARD_NO_PIN, hhmm, open_days, seg_from, seg_to)
                    if "0" in open_days:
                        add(TASK_CARD_IN_PIN, hhmm, "".join("1" if c == "0" else "0" for c in open_days), seg_from, seg_to)
            for day in special:
                base = datetime.datetime.combine(day, datetime.time())
                for hhmm in times:
                    h, m = map(int, hhmm.split(":"))
                    at = base + datetime.timedelta(hours=h, minutes=m)
                    state = group_allows(item, at, holidays)
                    if hhmm == "00:00" or state != group_allows(item, at - datetime.timedelta(minutes=1), holidays):
                        add(TASK_CARD_NO_PIN if state else TASK_CARD_IN_PIN, hhmm, "1111111", day, day)
            add(TASK_CARD_NO_PIN if group_allows(item, now, holidays) else TASK_CARD_IN_PIN, now.strftime("%H:%M"),
                "1111111", today, today)
    return tasks


def entry_tasks_fit(cfg, plan, now):
    """Zadania godzin wejścia, gdy mieszczą się w liście zadań kontrolera (WG_TASKS_MAX). Najdroższe są
    pojedyncze dni w kalendarzu: każdy dzieli zadania tygodniowe na osobne zakresy dat, a wszystko liczy
    się razy liczba drzwi z ograniczeniem (np. święta ustawowe na rok naprzód to ok. 112 zadań na jedne
    drzwi). Zapis, który się nie mieści, zostawiłby kontroler z niepełnym harmonogramem."""
    tasks = entry_hours_tasks(cfg, plan, now)
    if len(tasks) > WG_TASKS_MAX:
        raise ControllerError(
            f"Godziny wejścia wymagają {len(tasks)} zadań, a lista zadań kontrolera mieści {WG_TASKS_MAX}. "
            f"Zmniejsz liczbę wyjątków w kalendarzu (teraz {len(cfg.get('holidays') or [])}), połącz sąsiednie "
            f"dni w jeden okres albo zdejmij ograniczenie z części drzwi.")
    return tasks


def migrate_entry_hours_v1(old, dept_ids, free_depts):
    """Konfiguracja do 1.7.0 ({nr_drzwi: {enabled, start, end, days}} + działy „o każdej porze”)
    -> godziny działów. Godziny pierwszych drzwi z ograniczeniem dostają wszystkie działy
    bez wyjątku i pracownicy bez działu (różne godziny na różnych drzwiach nie mają odpowiednika)."""
    doors = {k: bool(v.get("enabled")) for k, v in old.items() if str(k).isdigit() and isinstance(v, dict)}
    first = next((old[k] for k in sorted(doors, key=int) if doors[k]), None)
    base = (dict(GROUP_DEFAULT, mode="hours", start=first.get("start", "10:00"), end=first.get("end", "18:00"),
                 days=first.get("days", "1111100")) if first else dict(GROUP_DEFAULT))
    if "1" not in base["days"]:
        base["mode"] = "none"
    groups = {str(d): dict(GROUP_DEFAULT, mode="always") if d in free_depts else dict(base) for d in dept_ids}
    groups[NODEPT] = dict(base)
    return {"doors": doors, "groups": groups}


def _bcd_date(d):
    return bytes.fromhex(f"{d.year:04d}{d.month:02d}{d.day:02d}")


def pack_task(t):
    return (_bcd_date(t["from"]) + _bcd_date(t["to"]) + bytes(int(c) for c in t["days"])
            + bytes.fromhex(t["start"].replace(":", "")) + bytes([t["door"], t["task"], 0]))


# --- warstwa sterowania jednym kontrolerem -----------------------------------
class AcbController:
    """Obsługuje pojedynczy kontroler rodziny ACB pod danym IP."""

    def __init__(self, host, user=DEF_USER, pwd=DEF_PWD):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.base = f"http://{host}"
        self.doors = 1
        self.model = "ACB-001"
        self.verified = True
        self.info = {}
        self.auto = None         # aktywny tryb auto-dodawania
        self.auto_last = None    # wynik ostatniego zakończonego trybu
        self.clock_min_align = False  # urządzenie ignoruje sekundy - ustawiaj na pełną minutę
        # wspólna bramka dla IP - patrz DeviceGate
        self.gate = gate(host)
        self.lock = self.gate.lock

    # -- niskopoziomowe --
    def _session(self):
        s = None      # stan logowania trzyma urządzenie; połączenie trzyma bramka
        r = self.gate.request("POST", self.base + "/ACT_ID_1",
                              data={"username": self.user, "pwd": self.pwd, "logId": "20101222"})
        if "AddCard" not in r.text and "ACT_ID_21" not in r.text:
            raise ControllerError("Logowanie nieudane (sprawdź login / hasło)")
        return s, r.text

    def _post(self, s, act, data=None):
        return self.gate.request("POST", f"{self.base}/{act}", session=s, data=data or {}).text

    @staticmethod
    def _clip(s, n=32):
        """Przycina tekst do n bajtów UTF-8 bez rozcinania znaku (np. polskich liter)."""
        return (s or "").encode("utf-8")[:n].decode("utf-8", "ignore")

    @staticmethod
    def _t(t):
        t = html.unescape(re.sub(r"<[^>]+>", " ", t))
        return re.sub(r"\s+", " ", t.replace("\xa0", " ")).strip(" ,")

    # -- rozpoznanie modelu --
    def detect(self):
        """Loguje się i ustala model po liczbie drzwi. Zwraca słownik info."""
        with self.lock:
            return self._detect_locked()

    def _extra(self):
        return {"model": self.model, "doors": self.doors, "verified": self.verified,
                "readers": MODELS.get(self.doors, {}).get("readers", ""),
                "host": self.host, "default_creds": (self.user, self.pwd) in FACTORY_CREDS,
                # fabryczne dane są publicznie znane - podajemy je interfejsowi tylko wtedy,
                # żeby formularz zmiany konta był od razu wypełniony
                "default_login": ({"user": self.user, "pwd": self.pwd}
                                  if (self.user, self.pwd) in FACTORY_CREDS else None)}

    def _detect_locked(self):
        s, menu = self._session()
        doors = len(set(re.findall(r"name=UNCLOSE(\d+)", menu)))
        if not doors:
            h = self._post(s, "ACT_ID_21", {"s5": "Configure"})
            doors = len(set(re.findall(r"#(\d+) (?:Door|号门)", h))) or 1
        prof = model_for_doors(doors)
        self.doors, self.model, self.verified = prof["doors"], prof["name"], prof["verified"]
        self.info = self._status(s)
        self.info.update(self._extra())
        return self.info

    # -- odczyt --
    # Strona Configure to tabela wierszy <td>etykieta</td><td>wartość</td><td>przycisk</td>.
    # Wiersze z przyciskiem rozpoznajemy po jego nazwie (niezależnej od języka):
    # E23 zegar, E30+n-1 nazwa drzwi n, E40+n-1 czas otwarcia drzwi n, E24 rejestr zdarzeń,
    # E25 Super Card, E12 sieć, E13 administrator, E17 język. Pozostałe - po etykiecie EN/ZH.
    LABELS = {
        "device_no": ("Device NO", "设备号"),
        "driver": ("Driver Version", "驱动版本"),
        "users_total": ("Users Total", "用户数"),
        "door_status": ("Door Status", "门状态"),
        "ip": ("IP",),
        "mask": ("Subnet mask", "掩码"),
        "gateway": ("Gateway", "网关"),
    }

    def _config_rows(self, h):
        rows, by_btn = [], {}
        for tr in re.findall(r"<tr\b[^>]*>(.*?)</tr>", h, re.S | re.I):
            cells = re.findall(r"<td\b[^>]*>(.*?)</td>", tr, re.S | re.I)
            if len(cells) < 2:
                continue
            label, value = self._t(cells[0]), self._t(cells[1])
            rows.append((label, value))
            for b in re.findall(r"name=['\"]?(E\d+)", tr):
                by_btn[b] = value
        return rows, by_btn

    def _status(self, s):
        h = self._post(s, "ACT_ID_21", {"s5": "Configure"})
        rows, by_btn = self._config_rows(h)

        def lbl(key):
            names = self.LABELS[key]
            for label, value in rows:
                if any(label == n or (len(n) > 2 and n in label) for n in names):
                    return value
            return ""

        doors = []
        for n in range(1, self.doors + 1):
            doors.append({"n": n,
                          "name": by_btn.get(f"E{29 + n}", ""),
                          "delay": by_btn.get(f"E{39 + n}", "")})
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", lbl("ip"))
        return {
            "device_no": lbl("device_no"),
            "driver": lbl("driver"),
            "clock": by_btn.get("E23", ""),
            "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),   # do porównania z zegarem kontrolera
            "door_name": doors[0]["name"] if doors else "",
            "open_delay": doors[0]["delay"] if doors else "",
            "users_total": lbl("users_total"),
            "door_status": zh_to_en(lbl("door_status")).strip(" ,"),
            "events": zh_to_en(by_btn.get("E24", "")),
            # anonimizacja: tylko liczba zapisanych Super Card, bez numerów
            "super_card": len(re.findall(r"\d+", by_btn.get("E25", ""))),
            "ip": ip.group(0) if ip else "",
            "mask": lbl("mask"),
            "gateway": lbl("gateway"),
            "manager": by_btn.get("E13", ""),
            "language": zh_to_en(by_btn.get("E17", "")) or "English",
            "ui_chinese": "网络门禁" in h,
            "doors_list": doors,
        }

    def status(self):
        with self.lock:
            s, _ = self._session()
            st = self._status(s)
            st.update(self._extra())
            self.info = st
            return st

    def _parse_users(self, h):
        h_ = re.sub(r"[ \t\n\r]+", " ", h)
        rows = []
        for m in re.finditer(
                r"<tr align=center><td>(\d+)</td><td>(.*?)</td><td>(.*?)</td>"
                r"<td>.*?name=E(\d+).*?name=D(\d+)", h_):
            rows.append({"user_id": m.group(1), "card": self._t(m.group(2)),
                         "name": self._t(m.group(3)),
                         "erow": int(m.group(4)), "drow": int(m.group(5))})
        tot = re.search(r"(?:Total Users|总人数)\s*[:：]\s*(\d+)", h_)
        return {"total": int(tot.group(1)) if tot else len(rows), "users": rows}

    def _search_users(self, s, keyword):
        # wyszukiwarka działa tylko ze strony Users (po samym logowaniu urządzenie
        # oddaje stronę Home); ukryte pola 22/23 wysyła też przeglądarka
        self._post(s, "ACT_ID_21", {"s2": "Users"})
        return self._parse_users(self._post(s, "ACT_ID_323", {"US21": self._clip(keyword), "22": "0",
                                                              "23": "", "24": "Search"}))

    @staticmethod
    def _next_page_form(h, action):
        """Pola formularza stronicowania (`action`) z przyciskiem „następna strona” (PN) albo None.
        Ukryte pola (PC, PE) odsyłamy z wartościami ze strony, jak przeglądarka."""
        i = h.find(f"action={action}")
        if i < 0:
            return None
        form = h[i:h.find("</form>", i) if h.find("</form>", i) > 0 else len(h)]
        data, nxt = [], None
        for tag in re.findall(r"<input\b[^>]*>", form, re.I):
            vals = AcbController._form_values(tag)
            if not vals:
                continue
            name, value = next(iter(vals.items()))
            if re.search(r"type\s*=\s*['\"]?hidden", tag, re.I):
                data.append((name, value))
            elif name == "PN":
                nxt = (name, value or "Next")
        return data + [nxt] if nxt else None

    def users(self, keyword="", all_pages=False, cards=None):
        """Użytkownicy ze strony WWW. `all_pages` - także ponad 20 pierwszych: kolejne strony formularzem
        stronicowania (ACT_ID_325), a karty, których i tak brakuje (`cards` - numery z kanału UDP), wyszukiwarką.
        Edycja i usuwanie użytkownika spoza pierwszej strony idą przez wyszukiwarkę (_find_user)."""
        with self.lock:
            s, _ = self._session()
            if keyword:
                d = self._search_users(s, keyword)
                return d
            h = self._post(s, "ACT_ID_21", {"s2": "Users"})
            d = self._parse_users(h)
            if not all_pages or d["total"] <= len(d["users"]):
                return d
            seen = {u["user_id"] for u in d["users"]}
            for _ in range(200):
                form = self._next_page_form(h, "ACT_ID_325")
                if form is None or len(seen) >= d["total"]:
                    break
                h = self._post(s, "ACT_ID_325", form)
                new = [u for u in self._parse_users(h)["users"] if u["user_id"] not in seen]
                if not new:
                    break
                seen.update(u["user_id"] for u in new)
                d["users"] += new
            if cards and len(seen) < d["total"]:
                have = {card_key(u["card"]) for u in d["users"]}
                for k in sorted({card_key(c) for c in cards} - have - {""}, key=int):
                    for u in self._search_users(s, k)["users"]:
                        if card_key(u["card"]) == k and u["user_id"] not in seen:
                            seen.add(u["user_id"])
                            d["users"].append(u)
            self._post(s, "ACT_ID_21", {"s2": "Users"})
            d["complete"] = len(d["users"]) >= d["total"]
            return d

    def card_names(self, cards):
        """Nazwy podanych kart: pierwsza strona listy Users (20 wierszy), pozostałe wyszukiwarką po
        numerze karty (szuka fragmentu - wyniki z innymi kartami też się przydają). Karta, której
        wyszukiwarka nie oddała, nie ma wpisu."""
        found = {card_key(u["card"]): u["name"] for u in self.users()["users"]}
        for k in sorted({card_key(k) for k in cards} - {""}, key=int):
            if k not in found:
                found.update({card_key(u["card"]): u["name"] for u in self.users(k)["users"]})
        return found

    # Formularz stronicowania (ACT_ID_345) ma ukryte pola PC (pozycja bieżącej
    # strony) i PE=0, wysyłane razem z przyciskiem - bez PC urządzenie skacze na
    # ostatnią stronę. PC ostatnio oglądanej strony pamiętamy w self.swipe_pc.
    SWIPE_BUTTONS = {"first": ("PF", "First"), "prev": ("PP", "Prev"),
                     "next": ("PN", "Next"), "last": ("PE", "Last"), "refresh": ("PF", "Refresh")}

    def _parse_swipe(self, h):
        m = re.search(r"name=PC value='(\d+)'", h)
        h_ = re.sub(r"[ \t\n\r]+", " ", h)
        rows = []
        for m2 in re.finditer(
                r"<tr class=([YN])><td>(\d+)</td><td>(.*?)</td>"
                r"<td>(.*?)</td><td>(.*?)</td><td>(.*?)</td>", h_):
            status = swipe_status(self._t(m2.group(5)))
            # status np. "Denied IN[#1 Door]" (ZH: "禁止 进门[#1号门]") - drzwi i czytnik
            # (każde drzwi mają czytnik wejścia i wyjścia: ACB-002 = 2 drzwi, 4 czytniki)
            door = re.search(r"#(\d+)", status)
            reader = re.search(r"\b(IN|OUT)\b", status, re.I)
            rows.append({"granted": m2.group(1) == "Y", "record": m2.group(2),
                         "card": self._t(m2.group(3)), "name": self._t(m2.group(4)),
                         "status": status, "time": self._t(m2.group(6)),
                         "door": int(door.group(1)) if door else None,
                         "reader": reader.group(1).lower() if reader else ""})
        page = (re.search(r"Page\D+(\d+)\D+Of\D+(\d+)", h_)
                or re.search(r"第\D*?(\d+)\D*?页\s*/\s*共\D*?(\d+)", h_))
        return {"rows": rows, "page": int(page.group(1)) if page else 1,
                "pages": int(page.group(2)) if page else 1, "pc": m.group(1) if m else None}

    def swipe(self, nav=None):
        with self.lock:
            s, _ = self._session()
            h = self._post(s, "ACT_ID_21", {"s4": "Swipe"})
            pc = getattr(self, "swipe_pc", None)
            if nav in self.SWIPE_BUTTONS and pc is not None:
                name, value = self.SWIPE_BUTTONS[nav]
                h = self._post(s, "ACT_ID_345", [("PC", pc), ("PE", "0"), (name, value)])
            p = self._parse_swipe(h)
            self.swipe_pc = p.pop("pc")
            return p

    def swipe_chunk(self, after=None, count=10):
        """Do `count` kolejnych stron logu pod jedną blokadą: od strony 1 (after=None) albo
        za stroną `after` (wynik poprzedniego wywołania). Między porcjami panel obsługuje
        inne zapytania - kolejną porcję zaczynamy od wejścia w Swipe i PC ostatniej strony."""
        out = []
        with self.lock:
            s, _ = self._session()
            cur = self._parse_swipe(self._post(s, "ACT_ID_21", {"s4": "Swipe"}))
            if after is None:
                out.append(cur)
            else:
                cur = after
            while len(out) < count and cur["page"] < cur["pages"] and cur["pc"] is not None:
                nxt = self._parse_swipe(self._post(s, "ACT_ID_345",
                                                   [("PC", cur["pc"]), ("PE", "0"), ("PN", "Next")]))
                if nxt["pc"] == cur["pc"] or nxt["page"] <= cur["page"]:
                    break                   # urządzenie nie przeszło dalej
                out.append(nxt)
                cur = nxt
            self.swipe_pc = cur["pc"]
        return out

    # -- użytkownicy --
    def add_card(self, card, name):
        if not re.fullmatch(r"\d{1,19}", card or ""):
            raise ControllerError("Numer karty musi być liczbą (do 19 cyfr)")
        _CARDS_NOW.pop(ctrl_key(self), None)
        with self.lock:
            s, _ = self._session()
            before = self._users_total(s)
            t = self._t(self._post(s, "ACT_ID_312",
                                   {"AD21": card, "AD22": self._clip(name), "25": "Add"}))
            # komunikat zależy od języka urządzenia - rozstrzyga licznik użytkowników
            if "Success" in t or self._users_total(s) > before:
                r = {"ok": True, "msg": f"Dodano kartę {card}"}
                if (w := card_warning(card)):
                    r["warning"] = w
                return r
            raise ControllerError(zh_to_en(t)[:160] or "Dodawanie nieudane")

    # -- auto-dodawanie przez przyłożenie karty --
    # Kontroler pozostaje w trybie auto-dodawania aż do wysłania Q1=Exit. Urządzenie
    # nie ma sesji (brak ciasteczek) - trzyma jeden globalny "stan strony", który
    # każde inne zapytanie panelu nadpisuje; Q1 wysłane poza stroną trybu jest
    # interpretowane jako inny przycisk. Dlatego wyjście zawsze wykonuje pełną
    # sekwencję wejście + natychmiastowe Exit. Tryb kończy się sam po wykryciu
    # nowej karty albo po AUTOADD_TIMEOUT sekundach.
    def _enter_auto(self, s):
        self._post(s, "ACT_ID_21", {"s1": "AddCard"})
        self._post(s, "ACT_ID_314", {"A1": "Auto Add by Swiping"})
        h = self._post(s, "ACT_ID_314", {"Y1": "Confirm Auto AddCard By Swiping"})
        if "swipe" not in h.lower() and "name=Q1" not in h and "刷卡" not in h:
            raise ControllerError("Kontroler nie włączył trybu auto-dodawania")

    def _users_total(self, s):
        return self._parse_users(self._post(s, "ACT_ID_21", {"s2": "Users"}))["total"]

    def _stop_auto_locked(self, reason):
        s, _ = self._session()
        self._enter_auto(s)
        h = self._post(s, "ACT_ID_314", {"Q1": "Exit"})
        # po wyjściu urządzenie wraca na stronę "Add Card" (przycisk A1 / tekst "Auto add")
        if "Auto add" not in h and "name=A1" not in h:
            raise ControllerError("Kontroler nie potwierdził wyjścia z trybu auto-dodawania")
        a, self.auto = self.auto, None
        added = 0
        if a:
            a["timer"].cancel()
            added = max(self._users_total(s) - a["before"], 0)
        self.auto_last = {"reason": reason, "added": added, "at": time.time()}
        return self.auto_state_locked()

    def _auto_timeout(self):
        try:
            with self.lock:
                if self.auto:
                    self._stop_auto_locked("timeout")
        except Exception:
            # kontroler chwilowo nie odpowiada - ponów za chwilę
            t = threading.Timer(5, self._auto_timeout)
            t.daemon = True
            t.start()

    def auto_state_locked(self):
        if not self.auto:
            return {"ok": True, "active": False, "last": self.auto_last}
        left = max(int(self.auto["until"] - time.time()), 0)
        return {"ok": True, "active": True, "left": left}

    def auto_add(self):
        with self.lock:
            if self.auto:
                return self.auto_state_locked()
            s, _ = self._session()
            before = self._users_total(s)
            self._enter_auto(s)
            timer = threading.Timer(AUTOADD_TIMEOUT, self._auto_timeout)
            timer.daemon = True
            timer.start()
            self.auto = {"before": before, "until": time.time() + AUTOADD_TIMEOUT, "timer": timer}
            self.auto_last = None
            return self.auto_state_locked()

    def auto_add_stop(self):
        with self.lock:
            return self._stop_auto_locked("manual")

    def auto_add_state(self):
        """Stan trybu; gdy przybył użytkownik - kończy tryb (jedna karta na raz)."""
        with self.lock:
            if self.auto:
                s, _ = self._session()
                if self._users_total(s) > self.auto["before"]:
                    return self._stop_auto_locked("card")
            return self.auto_state_locked()

    def _find_user(self, s, user_id, card=""):
        """Wiersz użytkownika z ustawionym kontekstem strony: lista Users, a gdy go na niej nie ma (ponad
        20 użytkowników) - wyniki wyszukiwarki po numerze karty (przyciski E/D działają z tej strony)."""
        for u in self._parse_users(self._post(s, "ACT_ID_21", {"s2": "Users"}))["users"]:
            if u["user_id"] == str(user_id):
                return u
        if card_key(card):
            for u in self._search_users(s, card_key(card))["users"]:
                if u["user_id"] == str(user_id):
                    return u
        raise ControllerError(f"Nie znaleziono użytkownika ID {user_id}")

    # Formularz edycji (ACT_ID_324, E<row>): USX<row> = nazwa, listy 24..27 = uprawnienia
    # do drzwi 1..4 (0 = zakaz, 1 = dostęp; nowa karta ma dostęp do wszystkich), S<row> = zapis.
    # Zapis wysyła pola w kolejności formularza z bieżącymi wartościami - zmienia się tylko to,
    # co podano (wcześniej panel wysyłał 24..27=1 i każda zmiana nazwy przywracała pełny dostęp).
    ACCESS_FIRST = 24

    def _user_form_locked(self, s, user_id, card=""):
        u = self._find_user(s, user_id, card)       # ustawia kontekst listy Users / wyszukiwarki
        r = u["erow"]
        h = self._post(s, "ACT_ID_324", {f"E{r}": "Edit"})
        form = h[h.find("action=ACT_ID_324"):] if "action=ACT_ID_324" in h else ""
        if f"USX{r}" not in form:
            self._post(s, "ACT_ID_21", {"s2": "Users"})
            raise ControllerError(f"Kontroler nie otworzył formularza użytkownika ID {user_id}")
        fields = [(k, v) for k, v in self._form_fields(form) if not re.fullmatch(r"[SC]\d+", k)]
        access = {}
        for k, v in fields:
            if k.isdigit() and 1 <= int(k) - self.ACCESS_FIRST + 1 <= self.doors:
                access[int(k) - self.ACCESS_FIRST + 1] = v == "1"
        return u, r, fields, access

    def user_detail(self, user_id, card=""):
        with self.lock:
            s, _ = self._session()
            u, _, fields, access = self._user_form_locked(s, user_id, card)
            self._post(s, "ACT_ID_21", {"s2": "Users"})        # wyjście bez zapisu
            return {"user_id": u["user_id"], "card": u["card"],
                    "name": dict(fields).get(f"USX{u['erow']}", u["name"]),
                    "access": [access.get(n) for n in range(1, self.doors + 1)]}

    def edit_user(self, user_id, name=None, access=None, card=""):
        """name=None - bez zmiany nazwy; access = {nr_drzwi: bool} - tylko podane drzwi."""
        access = {int(k): bool(v) for k, v in (access or {}).items()}
        for n in access:
            if n < 1 or n > self.doors:
                raise ControllerError(f"Ten model ma drzwi 1..{self.doors}")
        with self.lock:
            s, _ = self._session()
            _, r, fields, cur = self._user_form_locked(s, user_id, card)
            if access and not cur:
                self._post(s, "ACT_ID_21", {"s2": "Users"})
                raise ControllerError("Formularz użytkownika nie ma uprawnień do drzwi")
            data = []
            for k, v in fields:
                if k == f"USX{r}" and name is not None:
                    v = self._clip(name)
                elif k.isdigit() and (int(k) - self.ACCESS_FIRST + 1) in access:
                    v = "1" if access[int(k) - self.ACCESS_FIRST + 1] else "0"
                data.append((k, v))
            data.append((f"S{r}", "Save"))
            self._post(s, "ACT_ID_324", data)
            # sprawdź odczytem
            _, _, fields2, after = self._user_form_locked(s, user_id, card)
            self._post(s, "ACT_ID_21", {"s2": "Users"})
            wrong = [n for n, v in access.items() if after.get(n) != v]
            if wrong or (name is not None and dict(fields2).get(f"USX{r}") != self._clip(name)):
                raise ControllerError(f"Kontroler nie zapisał zmian użytkownika ID {user_id}"
                                      + (f" (drzwi: {', '.join(map(str, wrong))})" if wrong else ""))
            return {"ok": True, "msg": f"Zapisano użytkownika ID {user_id}",
                    "access": [after.get(n) for n in range(1, self.doors + 1)]}

    def delete_user(self, user_id, card=""):
        _CARDS_NOW.pop(ctrl_key(self), None)
        with self.lock:
            s, _ = self._session()
            r = self._find_user(s, user_id, card)["drow"]
            self._post(s, "ACT_ID_324", {f"D{r}": "Delete"})
            h = self._post(s, "ACT_ID_324", {f"X{r}": "OK"})
            t = "" if any(m in h for m in LOGIN_MARKERS) else self._t(h)[:120]
            return {"ok": True, "msg": t or f"Usunięto użytkownika ID {user_id}"}

    # -- reset do ustawień domyślnych --
    # Urządzenie nie ma funkcji resetu fabrycznego (patrz acs_diag.py), więc reset
    # składamy z pojedynczych operacji. Dane administratora zmieniamy NA KOŃCU -
    # jeśli coś wcześniej się nie uda, panel nie traci dostępu do kontrolera.
    RESET_LOGIN = ("abc", "654321")

    def factory_reset(self):
        done = []
        with self.lock:
            if self.auto:
                self._stop_auto_locked("manual")
                done.append("wyłączono tryb auto-dodawania")

            # 1. użytkownicy / karty - zawsze usuwamy pierwszy wiersz i sprawdzamy licznik
            s, _ = self._session()
            first = None
            while True:
                lst = self._parse_users(self._post(s, "ACT_ID_21", {"s2": "Users"}))
                if first is None:
                    first = lst["total"]
                if lst["total"] == 0:
                    break
                if not lst["users"]:
                    raise ControllerError(f"Licznik pokazuje {lst['total']} użytkowników, "
                                          "ale lista jest pusta - przerwano reset")
                u = lst["users"][0]
                self._post(s, "ACT_ID_324", {f"D{u['drow']}": "Delete"})
                self._post(s, "ACT_ID_324", {f"X{u['drow']}": "OK"})
                after = self._parse_users(self._post(s, "ACT_ID_21", {"s2": "Users"}))["total"]
                if after >= lst["total"]:
                    raise ControllerError(f"Nie udało się usunąć użytkownika ID {u['user_id']} "
                                          f"(karta {u['card']}) - przerwano reset")
            done.append(f"usunięto użytkowników/kart: {first}")

            # 2. hasła otwarcia z klawiatury (4 sloty) i Super Card (2 sloty)
            for door in range(1, self.doors + 1):
                for slot in (1, 2, 3, 4):
                    self.set_door_password("", slot, door)
            done.append(f"wyczyszczono hasła otwarcia ({4 * self.doors} sloty, drzwi: {self.doors})")
            for slot in (1, 2):
                self.set_super_card("", slot)
            done.append("wyczyszczono Super Card (2 sloty)")

            # 3. weryfikacja przed zmianą konta
            s, _ = self._session()
            st = self._status(s)
            cards = self._read_super_cards_locked(s)
            if st["users_total"] not in ("", "0") or any(cards):
                raise ControllerError("Po resecie na kontrolerze nadal są dane "
                                      f"(użytkownicy: {st['users_total']}, zajęte sloty Super Card: {sum(map(bool, cards))})")

            # 4. konto administratora
            if (self.user, self.pwd) != self.RESET_LOGIN:
                self.set_admin(self.user, self.pwd, *self.RESET_LOGIN)
            done.append("ustawiono login „abc” i hasło „654321”")
            self.info = self._status(self._session()[0])
            self.info.update(self._extra())
            return done

    # -- drzwi --
    def open_door(self, n=1):
        n = int(n)
        if n < 1 or n > self.doors:
            raise ControllerError(f"Ten model ma drzwi 1..{self.doors}")
        with self.lock:
            s, _ = self._session()
            h = self._post(s, "ACT_ID_701", {f"UNCLOSE{n}": "Remote Open"})
            t = "" if any(m in h for m in LOGIN_MARKERS) else self._t(h)[:120]
            return {"ok": True, "msg": t or f"Otwarto drzwi #{n}"}

    # -- konfiguracja --
    # Kody pól drzwi n (potwierdzone formularzami ACB-001 i ACB-002):
    #   nazwa        E<29+n> / S<29+n>, pole COXDOOR21 (to samo dla każdych drzwi)
    #   czas otwarcia E<39+n> / S<39+n>, pole COXDELAY21
    #   hasła         E<49+n>, sloty PWD<4(n-1)+1..4n>, zapis S<17+4(n-1)..20+4(n-1)>
    # Kody S17/S23/S24 powtarzają się w innych formularzach (język, zegar, zdarzenia) -
    # urządzenie rozróżnia je po stronie, na której jest (wcześniejsze E<xx>).
    def _enter(self, s, ebtn):
        self._post(s, "ACT_ID_21", {"s5": "Configure"})
        return self._post(s, "ACT_ID_355", {ebtn: "Edit"})

    def _door(self, door):
        try:
            door = int(door)
        except (TypeError, ValueError):
            door = 0
        if door < 1 or door > self.doors:
            raise ControllerError(f"Ten model ma drzwi 1..{self.doors}")
        return door

    def set_door_name(self, name, door=1):
        door = self._door(door)
        with self.lock:
            s, _ = self._session()
            self._enter(s, f"E{29 + door}")
            self._post(s, "ACT_ID_355", {"COXDOOR21": self._clip(name), f"S{29 + door}": "Save"})
            return {"ok": True, "msg": f"Zapisano nazwę drzwi #{door}"}

    def set_door_delay(self, sec, door=1):
        door = self._door(door)
        if not re.fullmatch(r"\d{1,3}", str(sec)) or int(sec) > 255:
            raise ControllerError("Czas otwarcia: 0-255 sekund")
        with self.lock:
            s, _ = self._session()
            self._enter(s, f"E{39 + door}")
            self._post(s, "ACT_ID_355", {"COXDELAY21": str(sec), f"S{39 + door}": "Save"})
            return {"ok": True, "msg": f"Drzwi #{door} - czas otwarcia: {sec} s"}

    def set_events(self, enabled):
        with self.lock:
            s, _ = self._session()
            self._enter(s, "E24")
            self._post(s, "ACT_ID_355", {"20": "1" if enabled else "2", "S24": "Save"})
            return {"ok": True, "msg": "Rejestr zdarzeń: " + ("włączony" if enabled else "wyłączony")}

    def set_language(self, lang):
        # formularz E17: radio 20 = 1 (Chinese) / 2 (English); zmiana działa od razu, bez restartu
        chinese = lang == "chinese"
        with self.lock:
            s, _ = self._session()
            h = self._enter(s, "E17")
            if "name=S17" not in h:
                self._post(s, "ACT_ID_21", {"s5": "Configure"})
                raise ControllerError("Kontroler nie otworzył formularza języka")
            h = self._post(s, "ACT_ID_355", {"20": "1" if chinese else "2", "S17": "Save"})
            if ("网络门禁" in h) != chinese:
                raise ControllerError("Kontroler nie zmienił języka")
            return {"ok": True, "msg": "Zmieniono język na " + ("chiński" if chinese else "angielski")}

    def ensure_english(self):
        """Przełącza chiński interfejs urządzenia na angielski. True = przełączono."""
        with self.lock:
            if not self.info.get("ui_chinese"):
                return False
            self.set_language("english")
            self.info = self._detect_locked()
            self.info["language_switched"] = True
            return True

    @staticmethod
    def _form_values(h):
        """Wartości pól <input> formularza: {nazwa: wartość}."""
        out = {}
        for tag in re.findall(r"<input\b[^>]*>", h, re.I):
            n = re.search(r"\bname\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s>]+))", tag, re.I)
            if not n:
                continue
            v = re.search(r"\bvalue\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s>]+))", tag, re.I)
            name = next(g for g in n.groups() if g is not None)
            out[name] = html.unescape(next((g for g in v.groups() if g is not None), "")) if v else ""
        return out

    @staticmethod
    def _form_fields(h):
        """Pola formularza (<input> i wybrana opcja <select>) w kolejności z dokumentu."""
        out = []
        for m in re.finditer(r"<input\b[^>]*>|<select\b[^>]*>.*?</select>", h, re.I | re.S):
            tag = m.group(0)
            if tag[:7].lower() == "<select":
                out.extend(AcbController._form_selects(tag).items())
            else:
                out.extend(AcbController._form_values(tag).items())
        return out

    @staticmethod
    def _form_selects(h):
        """Wybrane opcje list <select>: {nazwa: wartość}."""
        out = {}
        for attrs, body in re.findall(r"<select\b([^>]*)>(.*?)</select>", h, re.I | re.S):
            n = re.search(r"\bname\s*=\s*['\"]?([^\s'\">]+)", attrs, re.I)
            opts = re.findall(r"<option\b([^>]*)>", body, re.I)
            sel = next((o for o in opts if re.search(r"\bselected\b", o, re.I)), opts[0] if opts else "")
            v = re.search(r"\bvalue\s*=\s*['\"]?([^'\">\s]*)", sel, re.I)
            if n and v:
                out[n.group(1)] = v.group(1)
        return out

    # Formularze E25 (Super Card) i E50 (hasła otwarcia): każdy slot to osobny
    # <form> z polami DESC<n> (ukryte) i PWD<n>. Super Card urządzenie zwraca
    # w value='...'; hasła otwarcia są typu password BEZ wartości - urządzenie
    # nigdy ich nie ujawnia (nie da się odczytać, czy slot jest zajęty).
    def _read_super_cards_locked(self, s):
        self._post(s, "ACT_ID_21", {"s5": "Configure"})
        v = self._form_values(self._post(s, "ACT_ID_355", {"E25": "Edit"}))
        self._post(s, "ACT_ID_21", {"s5": "Configure"})     # wyjście z edycji bez zapisu
        if "PWD1" not in v:
            raise ControllerError("Nie udało się odczytać formularza Super Card")
        return [v.get("PWD1", ""), v.get("PWD2", "")]

    def read_codes(self):
        """Odczyt bez zapisu. Kody są anonimizowane - do przeglądarki trafia tylko informacja,
        czy slot jest zajęty (True/False), nigdy sam numer Super Card ani hasło. Hasła otwarcia
        są zwykle nieodczytywalne (None = nie wiadomo, czy slot jest zajęty)."""
        with self.lock:
            s, _ = self._session()
            cards = self._read_super_cards_locked(s)
            doors = []
            for door in range(1, self.doors + 1):
                pv = self._form_values(self._enter(s, f"E{49 + door}"))
                self._post(s, "ACT_ID_21", {"s5": "Configure"})
                # gdyby inny firmware jednak zwracał hasła - pokaż je
                first = 4 * (door - 1) + 1
                doors.append([bool(pv.get(f"PWD{first + k}")) for k in range(4)])
            readable = any(any(p) for p in doors)
            if not readable:
                doors = [[None] * 4 for _ in doors]
            return {"super_cards": [bool(c) for c in cards], "door_passwords": doors,
                    "passwords_readable": readable}

    def set_super_card(self, card, slot=1):
        if card and not re.fullmatch(r"\d{1,19}", card):
            raise ControllerError("Super Card: liczba do 19 cyfr (lub puste)")
        with self.lock:
            s, _ = self._session()
            slot = int(slot)
            self._enter(s, "E25")
            save = {1: "S33", 2: "S34"}[slot]
            self._post(s, "ACT_ID_355", {f"DESC{slot}": "", f"PWD{slot}": card or "", save: "Save"})
            # sprawdź odczytem, że urządzenie przyjęło wartość
            cards = self._read_super_cards_locked(s)
            if cards[slot - 1] != (card or ""):
                raise ControllerError(f"Kontroler nie zapisał Super Card w slocie {slot} "
                                      f"(odczytano: {'inny numer' if cards[slot - 1] else 'pusty'})")
            return {"ok": True, "super_cards": [bool(c) for c in cards],
                    "msg": f"Super Card slot {slot}: " + ("zapisano" if card else "wyczyszczono")}

    def set_door_password(self, pwd, slot=1, door=1):
        if pwd and not re.fullmatch(r"\d{1,6}", pwd):
            raise ControllerError("Hasło otwarcia: do 6 cyfr")
        door = self._door(door)
        slot = int(slot)
        if slot not in (1, 2, 3, 4):
            raise ControllerError("Slot hasła: 1-4")
        with self.lock:
            s, _ = self._session()
            h = self._enter(s, f"E{49 + door}")
            idx = 4 * (door - 1) + slot                 # drzwi 1: PWD1..4, drzwi 2: PWD5..8
            save = f"S{16 + idx}"                       # drzwi 1: S17..20, drzwi 2: S21..24
            if not (re.search(rf"name=['\"]?PWD{idx}\b", h) and re.search(rf"name=['\"]?{save}\b", h)):
                self._post(s, "ACT_ID_21", {"s5": "Configure"})
                raise ControllerError(f"Kontroler nie otworzył formularza haseł drzwi #{door}")
            self._post(s, "ACT_ID_355", {f"DESC{idx}": "", f"PWD{idx}": pwd or "", save: "Save"})
            return {"ok": True, "msg": f"Drzwi #{door}, hasło {slot}: " + ("zapisano" if pwd else "wyczyszczono")}

    def set_admin(self, old_name, old_pwd, new_name, new_pwd):
        if not new_name or not new_pwd:
            raise ControllerError("Podaj nowy login i nowe hasło")
        with self.lock:
            s, _ = self._session()
            self._enter(s, "E13")
            self._post(s, "ACT_ID_355", {"COXOP21": old_name, "COXOP22": old_pwd,
                       "COXOP23": new_name, "COXOP24": new_pwd, "COXOP25": new_pwd,
                       "S13": "Save"})
            # urządzenie nie zgłasza błędu wprost - sprawdź, czy nowe dane działają
            prev = (self.user, self.pwd)
            self.user, self.pwd = new_name, new_pwd
            try:
                self._session()
            except ControllerError:
                self.user, self.pwd = prev
                raise ControllerError("Kontroler nie przyjął zmiany - sprawdź obecny login i hasło")
            self.info.update(self._extra())
            return {"ok": True, "msg": "Zmieniono dane administratora"}

    def set_network(self, ip, gateway):
        for v in (ip, gateway):
            if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v or ""):
                raise ControllerError("Podaj poprawny adres IP i bramy")
        with self.lock:
            s, _ = self._session()
            h = self._enter(s, "E12")
            if "name=S12" not in h:
                self._post(s, "ACT_ID_21", {"s5": "Configure"})
                raise ControllerError("Kontroler nie otworzył formularza sieci")
            new = dict(zip(("COXIP21", "COXIP22", "COXIP23", "COXIP24"), ip.split(".")))
            new.update(zip(("COXIP26", "COXIP27", "COXIP28", "COXIP29"), gateway.split(".")))
            # Pola wysyłamy W KOLEJNOŚCI FORMULARZA, z bieżącymi wartościami pól ukrytych i list
            # (ACB-002: 20=tryb IP, 25=maska między IP a bramą). Firmware czyta je po kolei -
            # maska dopisana na końcu daje "HTTP PORT invalid!" i zapis jest odrzucany.
            form = h[h.find("action=ACT_ID_355"):] if "action=ACT_ID_355" in h else ""   # bez menu ACT_ID_21
            data = [(k, new.get(k, v)) for k, v in self._form_fields(form)
                    if not re.fullmatch(r"[SC]\d+", k)]
            if not any(k == "COXHTTPPORT" for k, _ in data):
                data.append(("COXHTTPPORT", "80"))
            data.append(("S12", "Save"))
            r = self._post(s, "ACT_ID_355", data)
            err = re.search(r"[^<>]{0,40}invalid[^<>]{0,10}", r, re.I)
            if err:
                raise ControllerError(f"Kontroler odrzucił zapis sieci: {self._t(err.group(0))}")
            if "Success" not in r and "成功" not in r:
                raise ControllerError("Kontroler nie potwierdził zapisu sieci: " + self._t(r)[:120])
            # "Successfully. Please Reboot the device" - nowe IP działa dopiero po restarcie
            self._reboot_locked(s)
            return {"ok": True, "host": ip,
                    "msg": f"Zapisano IP {ip} i zrestartowano kontroler - panel łączy się z nowym adresem"}

    def _reboot_locked(self, s):
        # E16 otwiera stronę "Please Confirm!" - restart następuje dopiero po Reboot=Reboot
        self._post(s, "ACT_ID_21", {"s5": "Configure"})
        h = self._post(s, "ACT_ID_355", {"E16": "Reboot"})
        if "name=Reboot" in h:
            try:
                self._post(s, "ACT_ID_355", {"Reboot": "Reboot"})
            except DeviceError:
                pass                    # urządzenie zrywa połączenie, restartując się
        self.gate.close()

    def udp(self):
        dev = str(self.info.get("device_no", ""))
        if not dev.isdigit():
            raise ControllerError("Nieznany numer urządzenia - połącz się z kontrolerem ponownie")
        return WgUdp(self.host, dev)

    def apply_entry_hours(self, cfg, plan):
        """Zastępuje CAŁĄ listę zadań kontrolera trybami drzwi z godzin wejścia (cfg - postać kanoniczna)."""
        with self.lock:
            wg = self.udp()
            now = wg.clock()
            tasks = entry_tasks_fit(cfg, plan, now)      # sprawdź PRZED wyczyszczeniem listy
            wg.ok(0xA6, WG_MAGIC, "czyszczenie listy zadań")
            for t in tasks:
                wg.ok(0xA8, pack_task(t), f"zadanie drzwi #{t['door']} o {t['start']}")
            wg.ok(0xAC, WG_MAGIC, "zatwierdzenie listy zadań")
            return {"tasks": len(tasks), "clock": now.strftime("%Y-%m-%d %H:%M:%S")}

    def reboot(self):
        with self.lock:
            s, _ = self._session()
            self._reboot_locked(s)
            return {"ok": True, "msg": "Restart wysłany - kontroler wróci za ok. minutę"}

    # -- zegar --
    # E23 ("Adjust Time") nie synchronizuje sam - otwiera formularz: listy 21=rok,
    # 22=miesiąc, 23=dzień, 24=godzina, 25=minuta, ukryte 26=sekundy ("00"),
    # zapis S23=Save. Wypełniamy go czasem serwera panelu (NTP). Jeśli urządzenie
    # ignoruje sekundy, zapis wykonujemy dokładnie na początku pełnej minuty.
    def _set_clock_locked(self, s, align_minute):
        if align_minute:
            # przejście do formularza zajmuje chwilę - zacznij ~3 s przed pełną minutą
            wait = (60 - time.time() % 60) - 3
            if wait < 0:
                wait += 60
            time.sleep(wait)
        self._post(s, "ACT_ID_21", {"s5": "Configure"})
        h = self._post(s, "ACT_ID_355", {"E23": "Adjust Time"})
        if "name=S23" not in h or "name=25" not in h:
            _dump("03_adjust_time.html", h)
            raise ControllerError("Kontroler nie otworzył formularza ustawiania czasu")
        if align_minute:
            rest = 60 - time.time() % 60
            if rest < 5:
                time.sleep(rest)
        lt = time.localtime(time.time() + 0.2)   # ~opóźnienie przetworzenia zapisu
        self._post(s, "ACT_ID_355", {
            "21": str(lt.tm_year), "22": str(lt.tm_mon), "23": str(lt.tm_mday),
            "24": str(lt.tm_hour), "25": str(lt.tm_min), "26": "%02d" % lt.tm_sec,
            "S23": "Save"})

    def _read_clock_locked(self, s):
        clock = self._status(s)["clock"]
        server = time.strftime("%Y-%m-%d %H:%M:%S")
        return clock, server, _clock_drift(clock, server)

    def adjust_time(self):
        with self.lock:
            s, _ = self._session()
            self._set_clock_locked(s, self.clock_min_align)
            clock, server, drift = self._read_clock_locked(s)
            if drift is not None and not self.clock_min_align and 2 < abs(drift) <= 61:
                # sekundy zostały zignorowane - powtórz z wyrównaniem do pełnej minuty
                self.clock_min_align = True
                self._set_clock_locked(s, True)
                clock, server, drift = self._read_clock_locked(s)
            if drift is None or abs(drift) > 2:
                raise ControllerError(f"Nie udało się ustawić czasu - kontroler: {clock}, "
                                      f"serwer: {server}")
            return {"ok": True, "msg": "Czas zsynchronizowany z serwerem panelu",
                    "clock": clock, "server_time": server, "drift": drift}


def _clock_drift(clock, server):
    """Urządzenie minus serwer w sekundach (ujemne = spóźnia się); None gdy nie da się ustalić."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        return int(time.mktime(time.strptime(clock, fmt)) - time.mktime(time.strptime(server, fmt)))
    except (ValueError, TypeError):
        return None


def _dump(name, text):
    try:
        d = os.path.join(DATA_DIR, "diag")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


# --- wyszukiwanie kontrolerów w sieci ----------------------------------------
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "192.168.1.1"
    finally:
        s.close()


def local_subnet():
    return f"{local_ip().rsplit('.', 1)[0]}.0/24"


def _local_ipv4s():
    """Adresy IPv4 tego komputera (bez pętli zwrotnej) - z nich idzie wyszukiwanie rozgłoszeniowe."""
    ips = {local_ip()}
    with contextlib.suppress(OSError):
        for ai in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(ai[4][0])
    return sorted(ip for ip in ips if not ip.startswith("127."))


# Fabryczne dane logowania rodziny ACB (widoczne jako domyślne w formularzu
# logowania urządzenia). Używane tylko do ROZPOZNANIA modelu podczas skanu,
# gdy dane podane przez użytkownika nie pasują.
FACTORY_CREDS = [("admin", "admin"), ("abc", "654321")]


def _probe(ip, user, pwd):
    """Sprawdza czy pod danym IP jest kontroler rodziny ACB. Zwraca dict lub None.
    Całość pod bramką IP - skan nie wchodzi w drogę operacjom aktywnego kontrolera."""
    ip = str(ip)
    with gate(ip).lock:
        return _probe_locked(ip, user, pwd)


def _probe_locked(ip, user, pwd):
    # Bez osobnego sprawdzania portu: każde połączenie TCP zużywa jedno z 11 miejsc
    # kontrolera, więc sprawdzenie portu i GET / idą tym samym (trwałym) połączeniem.
    g = gate(ip)
    r = None
    for attempt in range(3):
        try:
            r = g.request("GET", f"http://{ip}/", timeout=3, connect_timeout=0.5)
            break
        except DeviceError as e:
            if not isinstance(e.__cause__, TimeoutError):
                break                       # host odrzuca połączenie / nieosiągalny
            time.sleep(0.1)                 # możliwy zgubiony pakiet SYN - ponów
    # strona logowania: tytuł "Web Controller" (EN) albo "网络门禁" (ZH, np. fabryczny ACB-002)
    if r is None or "ACT_ID_1" not in r.text or not any(m in r.text for m in LOGIN_MARKERS):
        g.close()                           # nie kontroler - nie trzymamy połączenia
        return None
    entry = {"host": ip, "is_controller": True,
             "model": "?", "doors": 0, "verified": False, "login": "",
             "device_no": "", "driver": "", "login_ok": False}
    # kandydaci na dane logowania: najpierw podane, potem fabryczne (bez duplikatów)
    cands = []
    if user:
        cands.append((user, pwd))
    for c in FACTORY_CREDS:
        if c not in cands:
            cands.append(c)
    for u, p in cands:
        try:
            info = AcbController(ip, u, p).detect()
            entry.update({"model": info["model"], "doors": info["doors"],
                          "verified": info["verified"], "device_no": info.get("device_no", ""),
                          "driver": info.get("driver", ""), "login_ok": True, "login": u})
            break
        except Exception:
            continue
    else:
        # model wychodzi dopiero po zalogowaniu - kontroler ma login/hasło inne niż podane i fabryczne
        entry["model"] = "nieznany - podaj login i hasło kontrolera"
    return entry


def discover(subnet=None, user=DEF_USER, pwd=DEF_PWD, workers=64):
    subnet = subnet or local_subnet()
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > 8192:
        raise ControllerError("Zbyt duża podsieć do skanowania - podaj węższy zakres (np. /24)")
    # Skanujemy CAŁY zakres włącznie z adresem sieci (.0) i broadcast (.255) -
    # kontroler może być ustawiony na dowolnym adresie, także .0.
    hosts = list(net) if net.num_addresses > 2 else [net.network_address]
    found = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(lambda ip: _probe(ip, user, pwd), hosts):
            if res:
                found.append(res)
    # Wyszukiwanie rozgłoszeniowe UDP znajduje też kontrolery z adresem spoza podsieci (np. po resecie
    # albo po pomyłce w ustawieniach sieci) - tych skan HTTP nie zobaczy, a adres da się im zmienić przez UDP.
    try:
        udp = wg_search()
    except OSError as e:
        _devlog(f"UDP wyszukiwanie - błąd: {e}")
        udp = []
    by_dev = {e["device_no"]: e for e in found if e["device_no"]}
    by_ip = {e["host"]: e for e in found}
    for u in udp:
        e = by_dev.get(u["device_no"]) or by_ip.get(u["ip"])
        if e is None:
            e = {"host": u["ip"], "is_controller": True, "model": "?", "doors": 0, "verified": False,
                 "login": "", "device_no": u["device_no"], "driver": "", "login_ok": False}
            found.append(e)
        # bez logowania numer urządzenia zna tylko UDP - bez niego „Ustaw adres IP” nie ma czego wysłać
        e["device_no"] = e["device_no"] or u["device_no"]
        e["udp"] = u
        e["reachable"] = u["reachable"] and (e.get("login_ok") or e["host"] in by_ip)
    found.sort(key=lambda e: (not e.get("reachable", True), tuple(int(x) for x in e["host"].split("."))))
    return {"subnet": subnet, "count": len(found), "controllers": found, "local_ip": local_ip()}


# --- wyszukiwanie i zmiana adresu przez UDP (jak program producenta) ----------
# 0x94 wysłane rozgłoszeniowo z numerem urządzenia 0 - odpowiada każdy kontroler w tym samym segmencie
# sieci, bez względu na swój adres IP. Odpowiedź: [8..11] IP, [12..15] maska, [16..19] brama,
# [20..25] MAC, [26..27] wersja (BCD, 0662 = V6.62), [28..31] data firmware (BCD).
# 0x96 (też rozgłoszeniowo, z numerem urządzenia): [8..11] IP, [12..15] maska, [16..19] brama,
# [20..23] 55 AA AA 55 - kontroler nie odpowiada, tylko przyjmuje nowy adres (sprawdzamy ponownym 0x94).
def _wg_broadcast(pkt, collect=None, timeout=0.0):
    socks = []
    for ip in _local_ipv4s():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((ip, 0))
        except OSError:
            s.close()
            continue
        socks.append(s)
    try:
        for _ in range(2):                  # UDP może zgubić pakiet - wysyłamy dwa razy
            for s in socks:
                ip = s.getsockname()[0]
                for dst in ("255.255.255.255", ip.rsplit(".", 1)[0] + ".255"):
                    with contextlib.suppress(OSError):
                        s.sendto(bytes(pkt), (dst, WG_PORT))
        end = time.monotonic() + timeout
        while collect is not None and socks and (left := end - time.monotonic()) > 0:
            ready, _, _ = select.select(socks, [], [], left)
            for s in ready:
                with contextlib.suppress(OSError):
                    d, _ = s.recvfrom(1024)
                    collect(d, s.getsockname()[0])
    finally:
        for s in socks:
            s.close()
    if not socks:
        raise OSError("brak interfejsu sieciowego IPv4")


def _ip4(b):
    return ".".join(str(x) for x in b[:4])


def wg_search(timeout=2.0):
    """Kontrolery odpowiadające na wyszukiwanie rozgłoszeniowe 0x94: lista słowników po numerze urządzenia."""
    pkt = bytearray(64)
    pkt[0], pkt[1] = 0x17, 0x94
    found = {}

    def collect(d, via):
        if len(d) < 32 or d[0] != 0x17 or d[1] != 0x94:
            return
        dev = struct.unpack_from("<I", d, 4)[0]
        ip, mask = _ip4(d[8:12]), _ip4(d[12:16])
        try:
            reachable = ipaddress.ip_address(via) in ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            reachable = False
        found[dev] = {"device_no": str(dev), "ip": ip, "mask": mask, "gateway": _ip4(d[16:20]),
                      "mac": ":".join(f"{x:02X}" for x in d[20:26]),
                      "firmware": f"V{d[26]:x}.{d[27]:02x}", "fw_date": d[28:32].hex(),
                      "via": via, "reachable": reachable}

    _wg_broadcast(pkt, collect, timeout)
    _devlog(f"UDP wyszukiwanie 0x94: {len(found)} kontroler(ów)")
    return sorted(found.values(), key=lambda e: e["ip"])


def _free_ip(ip):
    """False, gdy pod adresem coś odpowiada (połączenie przyjęte albo odrzucone = host istnieje)."""
    for port in (80, 443):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        try:
            s.connect((ip, port))
            return False
        except ConnectionRefusedError:
            return False
        except OSError:
            pass
        finally:
            s.close()
    return True


def _check_new_ip(ip, mask, gateway):
    """Wspólne sprawdzenie nowego adresu kontrolera: poprawny adres w sieci tego komputera (inaczej panel
    straciłby z nim kontakt), brama w tej samej sieci. Zwraca (adres, sieć, brama albo None)."""
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        gw = ipaddress.ip_address(gateway) if gateway and gateway != "0.0.0.0" else None
    except ValueError:
        raise ControllerError("Podaj poprawny adres IP, maskę i bramę")
    if addr.version != 4 or net.prefixlen < 8 or net.prefixlen > 30:
        raise ControllerError("Maska musi być w zakresie 255.0.0.0 - 255.255.255.252")
    if addr in (net.network_address, net.broadcast_address):
        raise ControllerError(f"{ip} to adres {'sieci' if addr == net.network_address else 'rozgłoszeniowy'} "
                              f"{net} - wybierz adres urządzenia (np. {net.network_address + 100})")
    if gw is not None and gw not in net:
        raise ControllerError(f"Brama {gateway} jest spoza sieci {net}")
    local = _local_ipv4s()
    if ip in local:
        raise ControllerError(f"{ip} to adres komputera z panelem")
    if not any(ipaddress.ip_address(x) in net for x in local):
        raise ControllerError(f"Adres {ip} jest spoza sieci tego komputera ({', '.join(local)}) - "
                              "panel nie widziałby kontrolera")
    return addr, net, gw


def wg_set_ip(device_no, ip, mask="255.255.255.0", gateway=""):
    """Nowy adres kontrolera znalezionego wyszukiwaniem UDP (działa także, gdy jego obecny adres jest
    spoza naszej podsieci). Po zmianie: poprawia adres na liście zapisanych i rozłącza stare połączenie."""
    try:
        dev = int(device_no)
    except ValueError:
        raise ControllerError("Podaj poprawny numer urządzenia")
    addr, net, gw = _check_new_ip(ip, mask, gateway)
    now = {e["device_no"]: e for e in wg_search(1.5)}
    cur = now.get(str(dev))
    if cur is None:
        raise ControllerError(f"Kontroler nr {dev} nie odpowiada na wyszukiwanie w sieci lokalnej")
    if cur["ip"] != ip and not _free_ip(ip):
        raise ControllerError(f"Adres {ip} jest zajęty przez inne urządzenie - wybierz inny")
    pkt = bytearray(64)
    pkt[0], pkt[1] = 0x17, 0x96
    struct.pack_into("<I", pkt, 4, dev)
    pkt[8:12] = addr.packed
    pkt[12:16] = net.netmask.packed
    pkt[16:20] = gw.packed if gw is not None else bytes(4)
    pkt[20:24] = WG_MAGIC
    struct.pack_into("<I", pkt, 40, next(_WG_SEQ) & 0x7FFFFFFF)
    old = cur["ip"]
    _devlog(f"UDP 0x96 zmiana adresu kontrolera {dev}: {old} -> {ip}/{net.prefixlen} brama {gateway or '-'}")
    _wg_broadcast(pkt)
    # kontroler przyjmuje adres po chwili (restart stosu sieciowego) - czekamy, aż zgłosi się z nowym
    deadline = time.monotonic() + 20
    while True:
        time.sleep(2)
        e = next((x for x in wg_search(1.5) if x["device_no"] == str(dev)), None)
        if e and e["ip"] == ip:
            break
        if time.monotonic() > deadline:
            raise ControllerError(f"Kontroler nr {dev} nie potwierdził nowego adresu {ip}"
                                  + (f" (zgłasza się jako {e['ip']})" if e else " (nie odpowiada)")
                                  + " - odczekaj chwilę i uruchom skan ponownie")
    # stare połączenie (pod poprzednim adresem) jest martwe - rozłączamy, zapisany wpis dostaje nowy adres
    was = CONNS.get(f"dev:{dev}")
    if was is not None:
        with contextlib.suppress(ControllerError):
            disconnect(f"dev:{dev}")
        was.gate.close()
    with SAVED_LOCK:
        items = _saved_load()
        e = saved_match(items, old, str(dev))
        if e is not None and e.get("device_no") == str(dev):
            e["host"] = ip
            _saved_write(items)
            _MANUAL_OFF.discard(e["id"])        # „Łącz sam” zadziała pod nowym adresem
    return {"ok": True, "host": ip, "old": old, "saved": bool(e is not None and e.get("device_no") == str(dev)),
            "msg": f"Kontroler nr {dev} ma teraz adres {ip}" + (f" (był {old})" if old != ip else "")}


# --- stan serwera: połączone kontrolery ---------------------------------------
# Panel może być połączony z kilkoma kontrolerami naraz (z każdym jednym trwałym połączeniem TCP).
# Zadania w tle - godziny wejścia, zdarzenia na żywo, powiadomienia, zegar, kopie - działają dla wszystkich
# połączonych. Interfejs pokazuje jeden kontroler: wybrany w sesji przeglądarki (każdy zalogowany użytkownik
# może oglądać inny). Kontroler w słowniku pod kluczem ctrl_key (numer urządzenia, przetrwa zmianę IP).
CONNS = {}
CONNS_LOCK = threading.RLock()
_REQ = threading.local()          # bieżące zapytanie HTTP: sesja użytkownika panelu


def connected():
    with CONNS_LOCK:
        return list(CONNS.values())


def is_connected(c):
    with CONNS_LOCK:
        return CONNS.get(ctrl_key(c)) is c


def current_controller():
    """Kontroler oglądany w bieżącej sesji; bez wyboru (albo po rozłączeniu wybranego) - pierwszy połączony."""
    sess = getattr(_REQ, "session", None)
    with CONNS_LOCK:
        c = CONNS.get(sess.get("ctrl")) if sess and sess.get("ctrl") else None
        if c is None and CONNS:
            c = sorted(CONNS.values(), key=lambda x: (saved_name(x).lower(), x.host))[0]
            if sess is not None:
                session_select(sess, ctrl_key(c))
        return c


def require_active():
    c = current_controller()
    if c is None:
        raise ControllerError("Nie połączono z żadnym kontrolerem")
    return c


# --- zapisane kontrolery ------------------------------------------------------
# Lista w pliku JSON (uprawnienia 600): nazwa, IP, login i - jeśli zaznaczono
# "zapamiętaj hasło" - hasło otwartym tekstem. Plik jest lokalny, jak sam panel.
SAVED_LOCK = threading.Lock()


def _saved_load():
    try:
        with open(SAVED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        raise ControllerError(f"Nie można odczytać pliku zapisanych kontrolerów: {e}")


def _saved_write(items):
    os.makedirs(os.path.dirname(SAVED_FILE) or ".", exist_ok=True)
    tmp = SAVED_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SAVED_FILE)


def _saved_public(e):
    pub = {k: e.get(k, "") for k in ("id", "name", "host", "user", "model", "device_no")}
    pub["has_pwd"] = bool(e.get("pwd"))
    pub["autoconnect"] = bool(e.get("autoconnect")) and bool(e.get("pwd"))
    return pub


def saved_match(items, host, device_no=""):
    """Wpis pasujący do kontrolera: najpierw po numerze urządzenia, potem po IP."""
    if device_no:
        for e in items:
            if e.get("device_no") == device_no:
                return e
    for e in items:
        if e.get("host") == host:
            return e
    return None


def saved_list():
    with SAVED_LOCK:
        saved = [_saved_public(e) for e in _saved_load()]
    conns = {(c.info.get("device_no", ""), c.host): c for c in connected()}
    for e in saved:
        e["online"] = online_public(e["id"])
        e["connected"] = any((e["device_no"] and dev == e["device_no"]) or host == e["host"] for dev, host in conns)
    return {"saved": saved, "online_poll": ONLINE_POLL, "connected": connected_list()}


def saved_name(c):
    with SAVED_LOCK:
        try:
            e = saved_match(_saved_load(), c.host, c.info.get("device_no", ""))
        except ControllerError:
            e = None
    return e["name"] if e else ""


def connected_list():
    cur = current_controller()
    return sorted(({"key": ctrl_key(c), "name": saved_name(c), "host": c.host, "model": c.model,
                    "device_no": c.info.get("device_no", ""), "current": c is cur} for c in connected()),
                  key=lambda x: (x["name"].lower() or "~", x["host"]))


def saved_autoconnect(sid, enabled):
    with SAVED_LOCK:
        items = _saved_load()
        e = next((x for x in items if x["id"] == sid), None)
        if e is None:
            raise ControllerError("Nie znaleziono zapisanego kontrolera")
        if enabled and not e.get("pwd"):
            raise ControllerError("Automatyczne łączenie wymaga zapamiętanego hasła - zapisz kontroler z hasłem")
        e["autoconnect"] = bool(enabled)
        _saved_write(items)
    return {"ok": True}


# --- czy zapisane kontrolery są online ------------------------------------------
# Bez logowania i bez TCP: odczyt zegara (0x32) przez UDP 60000 z numerem urządzenia z zapisanego
# wpisu. Nie zajmuje miejsca na połączenie WWW kontrolera, więc nie przeszkadza aktywnemu kontrolerowi,
# a odpowiedź z innym numerem (inne urządzenie pod tym IP) nie liczy się jako online.
ONLINE_POLL = max(5.0, float(os.environ.get("ACS_ONLINE_POLL", "30")))
_ONLINE = {}                 # id wpisu -> stan ostatniego sprawdzenia
_ONLINE_LOCK = threading.Lock()
_ONLINE_WAKE = threading.Event()


def _online_probe(e):
    dev = str(e.get("device_no", ""))
    if not dev.isdigit():
        return "unknown", "Panel nie zna numeru urządzenia - połącz się z kontrolerem raz, aby go zapamiętał"
    try:
        WgUdp(e["host"], dev).request(0x32, quiet=True, tries=2, log_errors=False)
        return "online", ""
    except Exception as ex:          # także błąd wysyłki (np. sieć nieosiągalna)
        return "offline", str(ex)


def _online_round():
    with SAVED_LOCK:
        try:
            items = _saved_load()
        except ControllerError:
            items = []
    if items:
        with ThreadPoolExecutor(max_workers=min(16, len(items))) as ex:
            results = list(ex.map(_online_probe, items))
    else:
        results = []
    now = time.time()
    with _ONLINE_LOCK:
        for e, (state, err) in zip(items, results):
            target = (e.get("host", ""), str(e.get("device_no", "")))
            prev = _ONLINE.get(e["id"])
            if prev is not None and prev["target"] != target:
                prev = None                          # zmiana IP / urządzenia - stan od nowa
            if prev is not None and prev["state"] != state:
                _devlog(f"ONLINE {target[0]} ({e.get('name', '')}) {prev['state']} -> {state}")
            same = prev is not None and prev["state"] == state
            _ONLINE[e["id"]] = {
                "state": state, "error": err, "target": target, "checked": now,
                "changed": prev["changed"] if same else now,
                "seen": now if state == "online" else (prev or {}).get("seen"),
                "notified": bool(same and prev.get("notified")),
                "was_notified_offline": bool((prev or {}).get("was_notified_offline")),
            }
        for k in set(_ONLINE) - {e["id"] for e in items}:
            del _ONLINE[k]
    _offline_check(items)


def _online_loop():
    while True:
        _ONLINE_WAKE.clear()
        try:
            _online_round()
        except Exception as ex:
            _devlog(f"ONLINE ERR {type(ex).__name__}: {ex}")
        _ONLINE_WAKE.wait(ONLINE_POLL)


def online_check_now():
    _ONLINE_WAKE.set()
    return {"ok": True}


def _when(ts):
    if not ts:
        return ""
    d = datetime.datetime.fromtimestamp(ts)
    return d.strftime("%H:%M" if d.date() == datetime.date.today() else "%d.%m %H:%M")


def online_public(sid):
    with _ONLINE_LOCK:
        o = _ONLINE.get(sid)
        if o is None:
            return {"state": "checking"}
        return {"state": o["state"], "error": o["error"], "ago": round(time.time() - o["checked"]),
                "since": _when(o["changed"]), "seen": _when(o["seen"])}


def active_info(c=None):
    """Info o kontrolerze (domyślnie oglądanym w sesji) uzupełnione o nazwę z listy zapisanych."""
    c = c or current_controller()
    if c is None:
        return None
    info = dict(c.info)
    with SAVED_LOCK:
        e = saved_match(_saved_load(), c.host, info.get("device_no", ""))
    info["saved_id"] = e["id"] if e else ""
    info["saved_name"] = e["name"] if e else ""
    info["key"] = ctrl_key(c)
    return info


def saved_save_active(name, remember_pwd):
    c = require_active()
    name = (name or "").strip()[:60]
    if not name:
        raise ControllerError("Podaj nazwę kontrolera")
    with SAVED_LOCK:
        items = _saved_load()
        e = saved_match(items, c.host, c.info.get("device_no", ""))
        if e is None:
            e = {"id": os.urandom(6).hex()}
            items.append(e)
        e.update({"name": name, "host": c.host, "user": c.user,
                  "pwd": c.pwd if remember_pwd else "",
                  "model": c.model, "device_no": c.info.get("device_no", "")})
        if not remember_pwd:
            e["autoconnect"] = False
        _saved_write(items)
    _ONLINE_WAKE.set()
    return {"ok": True, "active": active_info()}


def saved_rename(sid, name):
    name = (name or "").strip()[:60]
    if not name:
        raise ControllerError("Podaj nazwę kontrolera")
    with SAVED_LOCK:
        items = _saved_load()
        for e in items:
            if e["id"] == sid:
                e["name"] = name
                _saved_write(items)
                return {"ok": True}
    raise ControllerError("Nie znaleziono zapisanego kontrolera")


def saved_delete(sid):
    with SAVED_LOCK:
        items = _saved_load()
        rest = [e for e in items if e["id"] != sid]
        if len(rest) == len(items):
            raise ControllerError("Nie znaleziono zapisanego kontrolera")
        _saved_write(rest)
    return {"ok": True}


def saved_connect(sid, pwd="", fallback=True):
    with SAVED_LOCK:
        e = next((x for x in _saved_load() if x["id"] == sid), None)
    if e is None:
        raise ControllerError("Nie znaleziono zapisanego kontrolera")
    c = connect(e["host"], e.get("user", ""), pwd or e.get("pwd", ""), fallback=fallback)["controller"]
    _MANUAL_OFF.discard(sid)
    # odśwież model / numer urządzenia w zapisanym wpisie
    with SAVED_LOCK:
        items = _saved_load()
        for x in items:
            if x["id"] == sid:
                x.update({"model": c.model, "device_no": c.info.get("device_no", "")})
        _saved_write(items)
    _ONLINE_WAKE.set()
    return {"ok": True, "active": active_info(c)}


def _saved_follow_active(c, **changes):
    """Po zmianie danych logowania / IP w panelu aktualizuje zapisany wpis."""
    with SAVED_LOCK:
        items = _saved_load()
        e = saved_match(items, c.host, c.info.get("device_no", ""))
        if e is None:
            return
        if "pwd" in changes and not e.get("pwd"):
            changes.pop("pwd")          # hasła nie zapamiętywano - nie zaczynaj
        e.update(changes)
        _saved_write(items)
    _ONLINE_WAKE.set()


def set_admin_active(old_name, old_pwd, new_name, new_pwd):
    c = require_active()
    r = c.set_admin(old_name, old_pwd, new_name, new_pwd)
    _saved_follow_active(c, user=new_name, pwd=new_pwd)
    return r


def factory_reset_active():
    c = require_active()
    # zapamiętaj wpis przed resetem (dopasowanie po numerze urządzenia / IP)
    with SAVED_LOCK:
        e = saved_match(_saved_load(), c.host, c.info.get("device_no", ""))
    done = c.factory_reset()
    try:
        c.apply_entry_hours(entry_hours_normalize({}, c.doors, []), PLAN_OFF)
        with db() as con:
            con.execute("DELETE FROM entry_hours WHERE ctrl = ?", (ctrl_key(c),))
            con.execute("DELETE FROM card_blocks WHERE ctrl = ?", (ctrl_key(c),))
        done.append("wyczyszczono godziny wejścia (lista zadań kontrolera)")
    except Exception as err:
        done.append(f"nie udało się wyczyścić godzin wejścia: {err}")
    if e:
        saved_delete(e["id"])
        done.append(f"usunięto z zapisanych kontrolerów („{e['name']}”)")
    return {"ok": True, "done": done, "active": active_info(c)}


def set_network_active(ip, gateway):
    old = require_active()
    ip, gateway = (ip or "").strip(), (gateway or "").strip()
    # formularz WWW kontrolera nie zmienia maski - nowy adres sprawdzamy z obecną
    mask = old.info.get("mask") or ""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", mask):
        mask = "255.255.255.0"
    _check_new_ip(ip, mask, gateway)
    if ip != old.host and not _free_ip(ip):
        raise ControllerError(f"Adres {ip} jest zajęty przez inne urządzenie - wybierz inny")
    r = old.set_network(ip, gateway)
    _saved_follow_active(old, host=ip)
    c = old
    if ip != old.host:
        # dalsza obsługa pod nowym adresem; model i ostatni status bez zmian, dopóki
        # kontroler nie wstanie po restarcie (odświeżanie statusu samo się połączy)
        c = AcbController(ip, old.user, old.pwd)
        c.doors, c.model, c.verified = old.doors, old.model, old.verified
        c.info = dict(old.info, ip=ip, host=ip)
        _register(c)
    r["active"] = active_info(c)
    return r


_MANUAL_OFF = set()          # zapisane kontrolery rozłączone ręcznie - bez automatycznego łączenia


def disconnect(key=""):
    c = CONNS.get(key) if key else require_active()
    if c is None:
        raise ControllerError("Ten kontroler nie jest połączony")
    if c.auto:
        try:
            c.auto_add_stop()           # nie zostawiaj urządzenia w trybie dodawania
        except Exception:
            pass
    with CONNS_LOCK:
        if CONNS.get(ctrl_key(c)) is c:
            del CONNS[ctrl_key(c)]
    with SAVED_LOCK:
        e = saved_match(_saved_load(), c.host, c.info.get("device_no", ""))
    if e:
        _MANUAL_OFF.add(e["id"])
    return {"ok": True, "connected": connected_list()}


def select_controller(key):
    with CONNS_LOCK:
        if key not in CONNS:
            raise ControllerError("Ten kontroler nie jest połączony")
    sess = getattr(_REQ, "session", None)
    if sess is not None:
        session_select(sess, key)
    return {"ok": True, "active": active_info(CONNS[key]), "connected": connected_list()}


def _offline_pull(c):
    """Tryb offline: po połączeniu dociąga log przejść z kontrolera, żeby czas pracy i log w panelu
    były aktualne bez klikania. Nie ma tu pętli - w trybie offline panel nie pracuje w tle."""
    try:
        swipe_sync_start(c)
    except Exception as e:
        _devlog(f"OFFLINE pobranie logu błąd: {e}")


def _register(c):
    """Dodaje kontroler do połączonych (zastępuje wcześniejszy obiekt tego samego urządzenia) i uruchamia
    dla niego wątki w tle. Wątki kończą się same, gdy obiekt przestaje być połączony."""
    key = ctrl_key(c)
    with CONNS_LOCK:
        old = CONNS.get(key)
        CONNS[key] = c
    if old is not None and old is not c and old.auto:
        try:
            old.auto_add_stop()
        except Exception:
            pass
    if OFFLINE:
        # tryb offline: żadnych zadań w tle przy kontrolerze (przełączanie PIN-ów, zdarzenia na żywo,
        # pilnowanie otwartych drzwi). Zamiast tego jedno pobranie logu przejść - po to panel się łączy.
        threading.Thread(target=_offline_pull, args=(c,), name=f"offline-pull-{key}", daemon=True).start()
    else:
        threading.Thread(target=_watch_loop, args=(c,), name=f"entry-watch-{key}", daemon=True).start()
        threading.Thread(target=_live_loop, args=(c,), name=f"live-{key}", daemon=True).start()
    sess = getattr(_REQ, "session", None)
    if sess is not None:
        session_select(sess, key)


def connect(host, user, pwd, fallback=True):
    if not host:
        raise ControllerError("Podaj adres IP kontrolera")
    # kandydaci: podane dane, potem fabryczne (bez duplikatów)
    cands = []
    if user:
        cands.append((user, pwd))
    for c in FACTORY_CREDS if fallback else ():
        if c not in cands:
            cands.append(c)
    for u, p in cands:
        try:
            c = AcbController(host, u, p)
            c.detect()
        except Exception:
            continue
        # fabryczny ACB-002 pracuje po chińsku - panel czyta oba języki, ale przełącza
        # urządzenie na angielski, żeby jego własny interfejs był czytelny
        if FORCE_ENGLISH:
            try:
                c.ensure_english()
            except ControllerError as e:
                c.info["language_error"] = str(e)
        _register(c)
        return {"ok": True, "active": active_info(c), "controller": c}
    raise ControllerError("Nie udało się zalogować - sprawdź login i hasło")


def connect_public(host, user, pwd):
    r = connect(host, user, pwd)
    r.pop("controller")
    return r


# --- dane panelu: działy, pracownicy, kopia logu przejść, czas pracy ----------
# Kontroler nie zna działów, a log przejść oddaje po 20 wpisów na stronę (najnowsze na
# stronie 1). Filtrowanie po pracowniku / dziale i liczenie czasu pracy wymagają całej
# historii, więc panel kopiuje log do lokalnej bazy SQLite - przyrostowo, do pierwszej
# strony z już znanymi wpisami. Działy i pracownicy są wspólni dla wszystkich kontrolerów
# (tę samą kartę pracownik przykłada do każdego z nich); pracownika rozpoznaje numer karty.
DB_FILE = os.environ.get("ACS_DB", os.path.join(DATA_DIR, "acb-panel.db"))
_DB_LOCK = threading.RLock()
_DB_READY = False
SCHEMA = """
CREATE TABLE IF NOT EXISTS departments(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS people(
  card TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', dept_id INTEGER);
CREATE TABLE IF NOT EXISTS door_tracking(
  ctrl TEXT NOT NULL, door INTEGER NOT NULL, role TEXT NOT NULL DEFAULT '', PRIMARY KEY(ctrl, door));
-- role (2.8.0): '' = drzwi z czytnikiem wejścia i wyjścia; 'in' / 'out' = drzwi, których każde odbicie jest
-- wejściem / wyjściem (kontroler z jednym czytnikiem na drzwi, ACB-004)
CREATE TABLE IF NOT EXISTS swipes(
  ctrl TEXT NOT NULL, record INTEGER NOT NULL, time TEXT NOT NULL,
  card TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', door INTEGER,
  reader TEXT NOT NULL DEFAULT '', granted INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT '', PRIMARY KEY(ctrl, record, time));
CREATE INDEX IF NOT EXISTS swipes_ctrl_time ON swipes(ctrl, time);
CREATE INDEX IF NOT EXISTS swipes_card_time ON swipes(ctrl, card, time);
CREATE TABLE IF NOT EXISTS sync_state(
  ctrl TEXT PRIMARY KEY, full_done INTEGER NOT NULL DEFAULT 0, cleared_to TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS entry_hours(
  ctrl TEXT PRIMARY KEY, config TEXT NOT NULL, applied TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS entry_free_depts(dept_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS entry_free_people(card TEXT PRIMARY KEY);
-- entry_free_*: wyjątki „o każdej porze” do 1.7.0, czytane już tylko przez migrację
CREATE TABLE IF NOT EXISTS entry_passes(
  ctrl TEXT NOT NULL, time TEXT NOT NULL, card TEXT NOT NULL, door INTEGER NOT NULL,
  record INTEGER NOT NULL, result TEXT NOT NULL DEFAULT '', PRIMARY KEY(ctrl, time, card, door));
-- 2.0.0: konta i sesje panelu, dziennik działań, ustawienia, blokady kart, zdarzenia na żywo, korekty czasu pracy
CREATE TABLE IF NOT EXISTS panel_users(
  id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'viewer', pwd TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  created TEXT NOT NULL DEFAULT '', last_login TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS panel_sessions(
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL NOT NULL, seen REAL NOT NULL,
  ip TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '', ctrl TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, time TEXT NOT NULL, login TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL, ctrl TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '',
  ok INTEGER NOT NULL DEFAULT 1, error TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS card_blocks(
  ctrl TEXT NOT NULL, card TEXT NOT NULL, doors TEXT NOT NULL, time TEXT NOT NULL,
  login TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(ctrl, card));
CREATE TABLE IF NOT EXISTS live_events(
  ctrl TEXT NOT NULL, record INTEGER NOT NULL, time TEXT NOT NULL, type INTEGER NOT NULL DEFAULT 0,
  granted INTEGER NOT NULL DEFAULT 0, door INTEGER NOT NULL DEFAULT 0, dir INTEGER NOT NULL DEFAULT 0,
  card TEXT NOT NULL DEFAULT '', reason INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ctrl, record, time));
CREATE INDEX IF NOT EXISTS live_events_time ON live_events(ctrl, time);
CREATE TABLE IF NOT EXISTS work_corrections(
  id INTEGER PRIMARY KEY, ctrl TEXT NOT NULL, card TEXT NOT NULL, time TEXT NOT NULL, reader TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', login TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, deleted TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS work_corrections_card ON work_corrections(ctrl, card, time);
CREATE TABLE IF NOT EXISTS notify_log(
  id INTEGER PRIMARY KEY, time TEXT NOT NULL, rule TEXT NOT NULL, title TEXT NOT NULL,
  text TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '');
-- 2.9.0: wymiany kart - stary numer karty należy do tej samej osoby co nowy (czas pracy, „kto w środku”)
CREATE TABLE IF NOT EXISTS card_replacements(
  old TEXT PRIMARY KEY, new TEXT NOT NULL, time TEXT NOT NULL, login TEXT NOT NULL DEFAULT '',
  ctrl TEXT NOT NULL DEFAULT '');
-- 2.1.0: drzwi, którym panel liczy czas otwarcia (kontroler nie wysyła alarmu „otwarte zbyt długo”)
CREATE TABLE IF NOT EXISTS door_open_watch(
  ctrl TEXT NOT NULL, door INTEGER NOT NULL, minutes INTEGER NOT NULL DEFAULT 5,
  PRIMARY KEY(ctrl, door));
"""
# dłuższy "pobyt" to prawie na pewno brak odbicia (zapomniane wyjście), nie praca
MAX_SESSION = 16 * 3600
LOG_PAGE_SIZE = 50


@contextlib.contextmanager
def db():
    global _DB_READY
    with _DB_LOCK:
        os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
        con = sqlite3.connect(DB_FILE, timeout=15)
        con.row_factory = sqlite3.Row
        try:
            if not _DB_READY:
                con.executescript(SCHEMA)
                _db_migrate(con)
                _DB_READY = True
            yield con
            con.commit()
        finally:
            con.close()


def _db_migrate(con):
    if con.execute("PRAGMA user_version").fetchone()[0] < 1:
        # 1.8.0: godziny wejścia per dział zamiast per drzwi
        depts = [r[0] for r in con.execute("SELECT id FROM departments")]
        free = {r[0] for r in con.execute("SELECT dept_id FROM entry_free_depts")}
        for r in con.execute("SELECT ctrl, config, applied FROM entry_hours").fetchall():
            vals = []
            for text in (r["config"], r["applied"]):
                try:
                    old = json.loads(text) if text else None
                except ValueError:
                    old = None
                vals.append(json.dumps(migrate_entry_hours_v1(old, depts, free), sort_keys=True)
                            if isinstance(old, dict) and "groups" not in old else text)
            con.execute("UPDATE entry_hours SET config = ?, applied = ? WHERE ctrl = ?", (*vals, r["ctrl"]))
        con.execute("PRAGMA user_version = 1")
    if con.execute("PRAGMA user_version").fetchone()[0] < 2:
        # 1.8.0: plan listy zadań zapisanej na kontrolerze (jedna zmiana / kilka zmian)
        if "plan" not in {r[1] for r in con.execute("PRAGMA table_info(entry_hours)")}:
            con.execute("ALTER TABLE entry_hours ADD COLUMN plan TEXT NOT NULL DEFAULT ''")
        con.execute("PRAGMA user_version = 2")
    if con.execute("PRAGMA user_version").fetchone()[0] < 3:
        # 2.6.0: log przejść wyczyszczony do tej chwili - starszych wpisów nie pobieramy ponownie
        if "cleared_to" not in {r[1] for r in con.execute("PRAGMA table_info(sync_state)")}:
            con.execute("ALTER TABLE sync_state ADD COLUMN cleared_to TEXT NOT NULL DEFAULT ''")
        con.execute("PRAGMA user_version = 3")
    if con.execute("PRAGMA user_version").fetchone()[0] < 4:
        # 2.7.0: kod powodu odmowy (strona WWW kontrolera go nie podaje - bierzemy z UDP 0xB0).
        # NULL = jeszcze nie sprawdzony, 0 = nie udało się ustalić.
        if "reason" not in {r[1] for r in con.execute("PRAGMA table_info(swipes)")}:
            con.execute("ALTER TABLE swipes ADD COLUMN reason INTEGER")
        con.execute("UPDATE swipes SET reason = (SELECT l.reason FROM live_events l WHERE l.ctrl = swipes.ctrl "
                    "AND l.record = swipes.record AND l.time = swipes.time) WHERE granted = 0 AND card <> ''")
        con.execute("PRAGMA user_version = 4")
    if con.execute("PRAGMA user_version").fetchone()[0] < 5:
        # 2.7.1: „Remote Open” ma w polu karty adres IP otwierającego - pulpit liczył go jako osobę w środku
        con.execute("UPDATE swipes SET card = '' WHERE status LIKE 'Remote Open%'")
        con.execute("PRAGMA user_version = 5")
    if con.execute("PRAGMA user_version").fetchone()[0] < 6:
        # 2.8.0: drzwi wejścia / wyjścia na kontrolerze z jednym czytnikiem na drzwi
        if "role" not in {r[1] for r in con.execute("PRAGMA table_info(door_tracking)")}:
            con.execute("ALTER TABLE door_tracking ADD COLUMN role TEXT NOT NULL DEFAULT ''")
        con.execute("PRAGMA user_version = 6")


# -- ustawienia panelu (JSON w tabeli settings) --
SETTINGS_DEFAULTS = {
    "work": {"norm_min": 480, "late_tolerance": 5, "holidays_pl": True, "depts": {}},
    "maintenance": {"clock_sync": True, "clock_max_drift": 5, "clock_check_hours": 6,
                    "backup": True, "backup_time": "02:30", "backup_keep": 14},
    "notify": {"email": {"enabled": False, "host": "", "port": 587, "security": "starttls", "user": "",
                         "password": "", "from": "", "to": ""},
               "telegram": {"enabled": False, "token": "", "chat_id": ""},
               "webhook": {"enabled": False, "url": ""},
               "cooldown": 10,
               "rules": {"denied_repeat": {"on": True, "count": 3, "minutes": 5},
                         "unknown_card": {"on": True},
                         "blocked_card": {"on": True},
                         "after_hours": {"on": False, "start": "06:00", "end": "20:00", "days": "1111100"},
                         "alarm": {"on": True},
                         "door_open": {"on": True},
                         "offline": {"on": True, "minutes": 5}}},
}


def _merge(default, value):
    if isinstance(default, dict) and isinstance(value, dict):
        out = {k: _merge(v, value.get(k)) for k, v in default.items()}
        out.update({k: v for k, v in value.items() if k not in default})
        return out
    if value is None or (default is not None and not isinstance(default, dict) and isinstance(value, dict)):
        return json.loads(json.dumps(default))
    return value


def setting(key):
    with db() as con:
        r = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    try:
        value = json.loads(r[0]) if r else None
    except ValueError:
        value = None
    return _merge(SETTINGS_DEFAULTS.get(key), value) if key in SETTINGS_DEFAULTS else value


def setting_save(key, value):
    with db() as con:
        con.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value, ensure_ascii=False)))


def card_key(card):
    """Numer karty bez zer poprzedzających - ta sama karta w logu i na liście użytkowników."""
    d = re.sub(r"\D", "", card or "")
    return d.lstrip("0") or ("0" if d else "")


# -- numer nadrukowany na karcie a numer widziany przez kontroler (Wiegand-26) --
# Czytnik przesyła do kontrolera tylko 24 młodsze bity numeru karty, rozbite na kod obiektu
# (8 bitów, "facility code") i numer karty (16 bitów). Kontroler skleja je z powrotem
# DZIESIĘTNIE, tak jakby dolna część miała zawsze 5 cyfr: numer = FC * 100000 + CN.
# Dlatego karta z nadrukiem 99999 trafia do logu jako 134463 (1 * 100000 + 34463).
# Pomiary na sprzęcie (ACB-002, kontroler "test 2 drzwiowy", 2026-09-18):
#   10000 -> 10000 | 12345 -> 12345 | 99999 -> 134463 | 100000 -> 134464 | 999999 -> 1516959
#   16777216 (= 256 * 65536) -> karta "zerowa", kontroler nie zapisuje jej w logu w ogóle.
WG_FC_MAX, WG_CN_MAX, WG_SPAN = 255, 65535, 1 << 24


def wg_read(card):
    """Numer z karty -> numer, który zobaczy kontroler. 0 = karta nie do użycia (same zera po obcięciu)."""
    k = card_key(card)
    if not k:
        return None
    fc, cn = divmod(int(k) % WG_SPAN, 1 << 16)
    return fc * 100000 + cn


def wg_card(number):
    """Numer z kontrolera -> najmniejszy numer karty, który go daje. None = numer nieosiągalny."""
    k = card_key(number)
    if not k:
        return None
    fc, cn = divmod(int(k), 100000)
    return None if cn > WG_CN_MAX or fc > WG_FC_MAX else fc * (1 << 16) + cn


def card_warning(card):
    """Ostrzeżenie dla numeru wpisanego ręcznie albo None, gdy numer jest w porządku."""
    k = card_key(card)
    if not k or not k.isdigit():
        return None
    n = int(k)
    if n <= WG_CN_MAX:
        return None                                   # do 65535 numer karty = numer w kontrolerze
    read = wg_read(k)
    if not read:
        return (f"Numer {k} jest wielokrotnością {WG_SPAN} - czytnik widzi taką kartę jako numer 0 "
                "i kontroler w ogóle jej nie rejestruje. Użyj innego numeru.")
    if wg_card(k) is None:
        return (f"Kontroler nigdy nie zgłosi numeru {k} (czytnik Wiegand-26 zgłasza numery, w których "
                f"pięć ostatnich cyfr nie przekracza {WG_CN_MAX}, a początek {WG_FC_MAX}). "
                f"Jeśli {k} to numer nadrukowany na karcie, wpisz {read}.")
    return (f"Jeśli {k} to numer nadrukowany na karcie, kontroler zobaczy ją jako {read} - wpisz ten numer. "
            f"Jeśli {k} pochodzi z logu przejść albo z listy kart, jest poprawny.")


def ctrl_key(c):
    """Kontroler w bazie: po numerze urządzenia (przetrwa zmianę IP), awaryjnie po adresie."""
    dev = c.info.get("device_no", "")
    return f"dev:{dev}" if dev else f"ip:{c.host}"


def _day(s, default=None):
    if not s:
        return default
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        raise ControllerError(f"Nieprawidłowa data: {s}")


# -- działy i pracownicy --
def departments():
    with db() as con:
        return [dict(r) for r in con.execute(
            "SELECT d.id, d.name, COUNT(p.card) AS people FROM departments d "
            "LEFT JOIN people p ON p.dept_id = d.id GROUP BY d.id ORDER BY d.name COLLATE NOCASE")]


def _dept_name(name):
    name = (name or "").strip()[:40]
    if not name:
        raise ControllerError("Podaj nazwę działu")
    return name


def dept_add(name):
    name = _dept_name(name)
    with db() as con:
        try:
            con.execute("INSERT INTO departments(name) VALUES (?)", (name,))
        except sqlite3.IntegrityError:
            raise ControllerError(f"Dział „{name}” już istnieje")
    return {"ok": True, "departments": departments()}


def dept_rename(dept_id, name):
    name = _dept_name(name)
    with db() as con:
        try:
            n = con.execute("UPDATE departments SET name = ? WHERE id = ?", (name, dept_id)).rowcount
        except sqlite3.IntegrityError:
            raise ControllerError(f"Dział „{name}” już istnieje")
    if not n:
        raise ControllerError("Nie znaleziono działu")
    return {"ok": True, "departments": departments()}


def dept_delete(dept_id):
    with db() as con:
        con.execute("UPDATE people SET dept_id = NULL WHERE dept_id = ?", (dept_id,))
        if not con.execute("DELETE FROM departments WHERE id = ?", (dept_id,)).rowcount:
            raise ControllerError("Nie znaleziono działu")
    pins_sync_all()
    return {"ok": True, "departments": departments()}


def _people_map(con):
    return {r["card"]: dict(r) for r in con.execute(
        "SELECT p.card, p.name, p.dept_id, d.name AS dept FROM people p "
        "LEFT JOIN departments d ON d.id = p.dept_id")}


def _log_names(con, key):
    """Ostatnia nazwa każdej karty z logu kontrolera (karta mogła zniknąć z urządzenia)."""
    return {r["card"]: r["name"] for r in con.execute(
        "SELECT card, name, MAX(time) FROM swipes WHERE ctrl = ? AND card <> '' AND name <> '' "
        "GROUP BY card", (key,))}


def people_list():
    """Zapisani pracownicy + karty widziane w logu aktywnego kontrolera (do filtrów)."""
    with db() as con:
        people = _people_map(con)
        c = current_controller()
        if c is not None:
            for card, name in _log_names(con, ctrl_key(c)).items():
                p = people.setdefault(card, {"card": card, "name": "", "dept_id": None, "dept": None})
                p["name"] = p["name"] or name
    return {"departments": departments(),
            "people": sorted(people.values(), key=lambda p: ((p["name"] or "~").lower(), p["card"]))}


def person_assign(card, name, dept_id):
    ck = card_key(card)
    if not ck:
        raise ControllerError("Brak numeru karty")
    dept = int(dept_id) if str(dept_id or "").strip() else None
    with db() as con:
        if dept is not None and not con.execute("SELECT 1 FROM departments WHERE id = ?", (dept,)).fetchone():
            raise ControllerError("Nie znaleziono działu")
        con.execute("INSERT INTO people(card, name, dept_id) VALUES (?, ?, ?) "
                    "ON CONFLICT(card) DO UPDATE SET dept_id = excluded.dept_id, "
                    "name = CASE WHEN excluded.name <> '' THEN excluded.name ELSE people.name END",
                    (ck, (name or "").strip()[:32], dept))
    out = {"ok": True, "departments": departments()}
    c = current_controller()
    if c is not None:
        res = entry_pins_sync(c)
        if res["error"]:
            out["warning"] = f"Nie zaktualizowano PIN-ów w kontrolerze: {res['error']}"
        elif res["changed"]:
            out["pins"] = res["changed"]
    pins_sync_all(skip=c)
    return out


# -- spis kart panelu --
# Tabela people to wspólny dla wszystkich kontrolerów spis „numer karty -> nazwa, dział”. Usunięcie karty
# z kontrolera go nie rusza (log przejść i czas pracy zachowują nazwisko), więc karta przyłożona potem do
# innego kontrolera dalej pokazuje się w logu z imieniem. Stąd ręczne „usuń ze spisu”.
def people_directory():
    checked, unchecked, where = [], [], {}
    for c in connected():
        name = saved_name(c) or c.host
        cards = _cards_now(c, max_age=0)
        if cards is None:
            unchecked.append(name)
            continue
        checked.append(name)
        for card in cards:
            where.setdefault(card, []).append(name)
    with db() as con:
        seen = {r[0]: r[1] for r in con.execute("SELECT card, MAX(time) FROM swipes WHERE card <> '' GROUP BY card")}
        rows = [dict(r) for r in con.execute(
            "SELECT p.card, p.name, p.dept_id, d.name AS dept FROM people p "
            "LEFT JOIN departments d ON d.id = p.dept_id")]
        alias = card_aliases(con)
    for r in rows:
        r["on"] = where.get(r["card"], [])
        r["last_seen"] = seen.get(r["card"]) or ""
        r["replaced_by"] = alias.get(r["card"], "")
    rows.sort(key=lambda r: (bool(r["on"]), (r["name"] or "~").lower(), r["card"]))
    return {"people": rows, "checked": checked, "unchecked": unchecked}


def person_forget(card):
    """Usuwa kartę ze spisu panelu (nazwa i dział). Tylko karty, których nie ma w żadnym połączonym
    kontrolerze - inaczej panel i tak odczytałby nazwę z powrotem przy następnym wczytaniu użytkowników."""
    ck = card_key(card)
    if not ck:
        raise ControllerError("Brak numeru karty")
    for c in connected():
        try:
            present = int(ck) <= 0xFFFFFFFF and c.udp().privilege(int(ck)) is not None
        except (ControllerError, OSError) as e:
            raise ControllerError(f"Nie sprawdzono, czy karta jest w kontrolerze {saved_name(c) or c.host} ({e}) - "
                                  "spróbuj ponownie")
        if present:
            raise ControllerError(f"Karta {ck} jest zapisana w kontrolerze {saved_name(c) or c.host} - najpierw usuń ją "
                                  "tam (Pracownicy i karty → Użytkownicy), inaczej nazwa wróci przy wczytaniu listy")
    with db() as con:
        if not con.execute("DELETE FROM people WHERE card = ?", (ck,)).rowcount:
            raise ControllerError("Tej karty nie ma w spisie panelu")
        con.execute("DELETE FROM entry_free_people WHERE card = ?", (ck,))
    return {"ok": True, "msg": f"Usunięto kartę {ck} ze spisu panelu", **people_directory()}


def _privileges_map(c):
    """{numer karty: uprawnienie} z kanału UDP albo None, gdy kanał nie odpowiada."""
    try:
        privs = [priv_parse(p) for p in c.udp().privileges()]
    except (ControllerError, OSError) as e:
        _devlog(f"Uprawnienia kart przez UDP - błąd: {e}")
        return None
    _CARDS[ctrl_key(c)] = {p["card"] for p in privs}
    return {p["card"]: p for p in privs}


def _card_public(p, blocked):
    if p is None:
        return {"valid_from": "", "valid_to": "", "blocked": blocked is not None, "validity": "unknown"}
    today = datetime.date.today()
    state = "ok"
    if blocked is not None or (p["doors"] and not any(p["doors"])):
        state = "blocked"
    elif p["to"] and p["to"] < today:
        state = "expired"
    elif p["from"] and p["from"] > today:
        state = "future"
    elif p["to"] and p["to"] != VALID_DEFAULT_TO and (p["to"] - today).days <= 7:
        state = "expiring"
    return {"valid_from": p["from"].isoformat() if p["from"] else "", "valid_to": p["to"].isoformat() if p["to"] else "",
            "blocked": state == "blocked", "block": blocked, "validity": state,
            "temporary": bool(p["to"]) and p["to"] != VALID_DEFAULT_TO}


def users_with_departments(keyword):
    """Lista użytkowników kontrolera z działami, ważnością i blokadami; zapamiętuje pracowników (karta -> nazwa)."""
    c = require_active()
    privs = _privileges_map(c)
    d = c.users(keyword, all_pages=not keyword, cards=list(privs) if privs else None)
    with db() as con:
        con.executemany("INSERT INTO people(card, name) VALUES (?, ?) ON CONFLICT(card) "
                        "DO UPDATE SET name = excluded.name WHERE excluded.name <> ''",
                        [(card_key(u["card"]), u["name"]) for u in d["users"] if card_key(u["card"])])
        people = _people_map(con)
        blocks = {r["card"]: dict(r) for r in con.execute("SELECT card, time, login, reason FROM card_blocks WHERE ctrl = ?",
                                                        (ctrl_key(c),))}
    for u in d["users"]:
        k = card_key(u["card"])
        p = people.get(k) or {}
        u["dept_id"], u["dept"] = p.get("dept_id"), p.get("dept")
        u.update(_card_public(privs.get(k) if privs else None, blocks.get(k)))
    d["departments"] = departments()
    d["udp"] = privs is not None
    if privs is not None and not keyword:
        d["complete"] = len(d["users"]) >= len(privs) or d.get("complete", True)
    return d


def _card_priv(c, card):
    k = card_key(card)
    if not k:
        raise ControllerError("Brak numeru karty")
    try:
        p = c.udp().privilege(k)
    except DeviceError as e:
        raise ControllerError(f"Ważność i blokada kart wymagają kanału UDP 60000 kontrolera: {e}")
    if p is None:
        raise ControllerError(f"Karty {k} nie ma w kontrolerze")
    return p


def card_validity(card, valid_from, valid_to):
    return card_validity_on(require_active(), card, valid_from, valid_to)


def card_validity_on(c, card, valid_from, valid_to):
    """Okres ważności karty zapisany w kontrolerze (UDP 0x50) - działa bez panelu."""
    d_from = _iso_day(valid_from, "data „ważna od”") if valid_from else datetime.date(2011, 1, 1)
    d_to = _iso_day(valid_to, "data „ważna do”") if valid_to else VALID_DEFAULT_TO
    if d_to < d_from:
        raise ControllerError("Data „ważna do” jest wcześniejsza niż „ważna od”")
    if not datetime.date(2000, 1, 1) <= d_from <= datetime.date(2099, 12, 31) or d_to > datetime.date(2099, 12, 31):
        raise ControllerError("Daty ważności: lata 2000–2099")
    p = _card_priv(c, card)
    p.update({"from": d_from, "to": d_to})
    after = c.udp().write_privilege(p)
    return {"ok": True, "card": after["card"], **_card_public(after, _block_row(c, after["card"])),
            "msg": f"Karta {after['card']}: ważna {d_from.isoformat()} – {d_to.isoformat()}"}


def _block_row(c, card):
    with db() as con:
        r = con.execute("SELECT card, time, login, reason FROM card_blocks WHERE ctrl = ? AND card = ?",
                        (ctrl_key(c), card_key(card))).fetchone()
    return dict(r) if r else None


def _block_one(c, card, reason):
    p = _card_priv(c, card)
    key, k = ctrl_key(c), p["card"]
    if _block_row(c, k) is None:
        doors = p["doors"] if any(p["doors"]) else [1] * c.doors + [0] * (4 - c.doors)
        sess = getattr(_REQ, "session", None)
        with db() as con:
            con.execute("INSERT OR REPLACE INTO card_blocks(ctrl, card, doors, time, login, reason) VALUES (?, ?, ?, ?, ?, ?)",
                        (key, k, ",".join(map(str, doors)), _now_str(), sess["login"] if sess else "system",
                         (reason or "").strip()[:120]))
    if any(p["doors"]):
        p["doors"] = [0, 0, 0, 0]
        c.udp().write_privilege(p)
    return k


def card_block(card, reason, everywhere=False):
    """Blokada karty: dostęp do wszystkich drzwi = 0 w kontrolerze (panel pamięta poprzednie uprawnienia).
    Karta zostaje w kontrolerze, więc log i czas pracy zachowują nazwisko; odblokowanie przywraca dostęp."""
    c = require_active()
    targets = [c] + ([x for x in connected() if x is not c] if everywhere else [])
    done, errors = [], []
    for x in targets:
        try:
            _block_one(x, card, reason)
            done.append(saved_name(x) or x.host)
        except ControllerError as e:
            if x is c:
                raise
            if "nie ma w kontrolerze" not in str(e):
                errors.append(f"{saved_name(x) or x.host}: {e}")
    return {"ok": True, "msg": f"Zablokowano kartę {card_key(card)}" + (f" ({', '.join(done)})" if len(done) > 1 else ""),
            "errors": errors}


def card_unblock(card):
    c = require_active()
    k = card_key(card)
    row = _block_row(c, k)
    p = _card_priv(c, k)
    if row is not None:
        with db() as con:
            doors = con.execute("SELECT doors FROM card_blocks WHERE ctrl = ? AND card = ?", (ctrl_key(c), k)).fetchone()[0]
        p["doors"] = [int(x) for x in doors.split(",")][:4]
    elif not any(p["doors"]):
        p["doors"] = [1] * c.doors + [0] * (4 - c.doors)
    c.udp().write_privilege(p)
    with db() as con:
        con.execute("DELETE FROM card_blocks WHERE ctrl = ? AND card = ?", (ctrl_key(c), k))
    return {"ok": True, "msg": f"Odblokowano kartę {k}"}


def edit_user_active(user_id, name, access, card=""):
    """Edycja przez stronę WWW kontrolera. Formularz WWW zna tylko dostęp 0/1 - po zapisie panel przywraca
    daty ważności karty, gdyby strona je nadpisała. Zablokowanej karty nie da się tak odblokować."""
    c = require_active()
    k = card_key(card)
    if access and k and _block_row(c, k) is not None and any(access.values()):
        raise ControllerError("Karta jest zablokowana - najpierw ją odblokuj")
    before = None
    if k:
        with contextlib.suppress(ControllerError, OSError):
            before = c.udp().privilege(k)
    r = c.edit_user(user_id, name, access, card)
    if before is not None:
        try:
            after = c.udp().privilege(k)
            if after is not None and (after["from"], after["to"]) != (before["from"], before["to"]):
                after.update({"from": before["from"], "to": before["to"]})
                c.udp().write_privilege(after)
                _devlog(f"Karta {k}: przywrócono daty ważności po zapisie strony WWW")
            if after is not None and after["pin"] != before["pin"]:
                threading.Thread(target=entry_pins_sync, args=(c,), daemon=True).start()
        except (ControllerError, OSError) as e:
            r["warning"] = f"Nie sprawdzono dat ważności karty po zapisie: {e}"
    return r


def add_card_active(card, name, valid_from="", valid_to=""):
    c = require_active()
    r = c.add_card(card, name)
    if valid_from or valid_to:
        try:
            r["validity"] = card_validity(card, valid_from, valid_to)
            r["msg"] += f", ważna do {r['validity']['valid_to']}"
        except ControllerError as e:
            r["warning"] = "\n".join(filter(None, [r.get("warning"),
                                                   f"Dodano kartę, ale nie ustawiono ważności: {e}"]))
    threading.Thread(target=entry_pins_sync, args=(c,), daemon=True).start()
    return r


def delete_user_active(user_id, card=""):
    c = require_active()
    r = c.delete_user(user_id, card)
    if card_key(card):
        with db() as con:
            con.execute("DELETE FROM card_blocks WHERE ctrl = ? AND card = ?", (ctrl_key(c), card_key(card)))
    return r


# -- wymiana karty (nowy numer dla tej samej osoby) --
# Strona WWW kontrolera nie pozwala zmienić numeru karty użytkownika, więc wymiana to: dodanie nowej karty
# pod tą samą nazwą (ACT_ID_312), skopiowanie uprawnienia starej karty (UDP 0x50: drzwi, daty ważności, PIN)
# i usunięcie starej (ACT_ID_324) - od tej chwili stara karta nie otwiera drzwi. W panelu zostaje wpis
# card_replacements: odbicia starej karty liczą się tej samej osobie (czas pracy, „kto w środku”), a nazwa
# i dział przechodzą na nowy numer. Kolejność kroków jest celowa: przy błędzie w połowie stara karta
# dalej działa, a panel mówi, co zostało do zrobienia.
def card_aliases(con):
    """{stary numer: aktualny numer} - łańcuchy wymian (A -> B -> C) rozwiązane do końca."""
    direct = {r[0]: r[1] for r in con.execute("SELECT old, new FROM card_replacements")}
    out = {}
    for old in direct:
        cur, seen = old, {old}
        while cur in direct and direct[cur] not in seen:
            cur = direct[cur]
            seen.add(cur)
        out[old] = cur
    return out


def card_group(con, card):
    """Numer karty z wszystkimi numerami, które zastąpił (do filtrów logu i raportu)."""
    k = card_key(card)
    alias = card_aliases(con)
    final = alias.get(k, k)
    return sorted({final, k} | {o for o, n in alias.items() if n == final})


def _new_card_check(new):
    k = card_key(new)
    if not re.fullmatch(r"\d{1,19}", (new or "").strip()):
        raise ControllerError("Nowy numer karty musi być liczbą (same cyfry, bez spacji)")
    if int(k) > 0xFFFFFFFF:
        raise ControllerError("Numer karty jest za duży - kontroler przyjmuje do 4294967295")
    if wg_read(k) == 0:
        raise ControllerError(f"Numer {k} czytnik widzi jako 0 - takiej karty kontroler nie zarejestruje")
    if wg_card(k) is None:
        raise ControllerError(f"Kontroler nigdy nie zgłosi numeru {k}. Jeśli to numer nadrukowany na karcie, "
                              f"wpisz {wg_read(k)} (patrz „Numer na karcie a numer w kontrolerze”).")
    return k


def _card_link(con, c, old, new, login):
    """Wpis wymiany + nazwa i dział starej karty przeniesione na nową (jeśli nowa ich nie ma)."""
    con.execute("INSERT INTO card_replacements(old, new, time, login, ctrl) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(old) DO UPDATE SET new = excluded.new, time = excluded.time, login = excluded.login, "
                "ctrl = excluded.ctrl", (old, new, _now_str(), login, ctrl_key(c) if c else ""))
    con.execute("DELETE FROM card_replacements WHERE old = ?", (new,))     # powrót do dawnego numeru
    p = con.execute("SELECT name, dept_id FROM people WHERE card = ?", (old,)).fetchone()
    if p:
        con.execute("INSERT INTO people(card, name, dept_id) VALUES (?, ?, ?) ON CONFLICT(card) DO UPDATE SET "
                    "name = CASE WHEN people.name = '' THEN excluded.name ELSE people.name END, "
                    "dept_id = COALESCE(people.dept_id, excluded.dept_id)", (new, p["name"], p["dept_id"]))


def _login_now():
    sess = getattr(_REQ, "session", None)
    return sess["login"] if sess else "system"


def card_replace(user_id, old, new):
    """Zmiana numeru karty użytkownika aktywnego kontrolera. Stara karta traci dostęp."""
    c = require_active()
    ko, kn = card_key(old), _new_card_check(new)
    if not ko:
        raise ControllerError("Brak dotychczasowego numeru karty")
    if ko == kn:
        raise ControllerError("Nowy numer jest taki sam jak dotychczasowy")
    if c.auto:
        raise ControllerError("Najpierw zakończ auto-dodawanie kart")
    if _block_row(c, ko) is not None:
        raise ControllerError("Karta jest zablokowana - najpierw ją odblokuj (blokada nie przechodzi na nowy numer)")
    old_p = _card_priv(c, ko)                                   # sprawdza też kanał UDP
    if c.udp().privilege(kn) is not None:
        raise ControllerError(f"Karta {kn} jest już zapisana w tym kontrolerze - wybierz inny numer "
                              "albo najpierw usuń tamtego użytkownika")
    if not str(user_id or "").strip():         # pytanie przy dodawaniu karty zna tylko numer
        hit = [u for u in c.users(ko)["users"] if card_key(u["card"]) == ko]
        if not hit:
            raise ControllerError(f"Nie znaleziono użytkownika z kartą {ko} na stronie kontrolera")
        user_id = hit[0]["user_id"]
    name = c.user_detail(user_id, ko)["name"]
    c.add_card(kn, name)
    try:
        c.udp().write_privilege(dict(old_p, card=kn))
    except (ControllerError, OSError) as e:
        raise ControllerError(f"Dodano kartę {kn}, ale nie skopiowano uprawnień starej karty ({e}). Stara karta {ko} "
                              f"nadal działa - sprawdź nową kartę w „Edytuj / dostęp” i usuń starą ręcznie.")
    try:
        c.delete_user(user_id, ko)
        still = c.udp().privilege(ko) is not None
    except (ControllerError, OSError) as e:
        raise ControllerError(f"Karta {kn} działa z uprawnieniami starej, ale nie usunięto karty {ko} ({e}) - "
                              "usuń ją ręcznie, inaczej dalej otwiera drzwi.")
    if still:
        raise ControllerError(f"Karta {kn} działa, ale kontroler nadal ma kartę {ko} - usuń ją ręcznie.")
    with db() as con:
        _card_link(con, c, ko, kn, _login_now())
    _CARDS_NOW.pop(ctrl_key(c), None)
    threading.Thread(target=entry_pins_sync, args=(c,), daemon=True).start()
    r = {"ok": True, "msg": f"Karta {ko} zamieniona na {kn} - stara karta nie otwiera już drzwi"}
    warn, others = [], []
    for x in connected():
        if x is c:
            continue
        with contextlib.suppress(ControllerError, OSError):
            if x.udp().privilege(ko) is not None:
                others.append(saved_name(x) or x.host)
    if others:
        warn.append(f"Stara karta {ko} jest nadal zapisana w kontrolerach: {', '.join(others)} - "
                    "zmień ją także tam.")
    if warn:
        r["warning"] = " ".join(warn)
    return r


CARD_PICK_MAX_AGE = 600      # s - odmowa starsza nie nadaje się na „numer właśnie przyłożonej karty”


def card_last_denied():
    """Numer ostatniej odrzuconej karty spoza kontrolera (z ostatnich 10 min) - kontroler podaje numer tak,
    jak go widzi, więc nic nie trzeba przeliczać z nadruku."""
    c = require_active()
    try:
        wg = c.udp()
        last = wg.last_event()
        evs = [last] + [wg.event(i) for i in range(last["record"] - 1, max(0, last["record"] - 20), -1)]
        clock = wg.clock(quiet=True)
    except (ControllerError, OSError) as e:
        raise ControllerError(f"Nie odczytano zdarzeń kontrolera (kanał UDP 60000): {e}")
    cards = _cards_now(c, max_age=0) or set()
    for e in evs:
        if e["type"] != WG_EVENT_SWIPE or e["granted"] or e["time"] is None:
            continue
        age = (clock - e["time"]).total_seconds()
        if age > CARD_PICK_MAX_AGE:
            break
        k = card_key(e["card"])
        if k and k not in cards:
            return {"card": k, "time": e["time"].strftime("%Y-%m-%d %H:%M:%S"), "door": e["door"],
                    "ago": int(max(age, 0))}
    raise ControllerError("W ostatnich 10 minutach nie było odmowy dla karty spoza kontrolera - przyłóż nową kartę "
                          "do czytnika (kontroler ją odrzuci) i spróbuj ponownie")


def card_link(old, new):
    """Wymiana zarejestrowana tylko w panelu: stara karta nie jest już w żadnym połączonym kontrolerze
    (np. usunięta przed 2.9.0), a nowa ma przejąć jej historię."""
    ko, kn = card_key(old), card_key(new)
    if not ko or not kn or not re.fullmatch(r"\d{1,19}", kn):
        raise ControllerError("Podaj numery obu kart (same cyfry)")
    if ko == kn:
        raise ControllerError("Numery kart są takie same")
    for x in connected():
        try:
            present = x.udp().privilege(int(ko)) is not None if int(ko) <= 0xFFFFFFFF else False
        except (ControllerError, OSError) as e:
            raise ControllerError(f"Nie sprawdzono kontrolera {saved_name(x) or x.host} ({e}) - spróbuj ponownie")
        if present:
            raise ControllerError(f"Karta {ko} jest nadal w kontrolerze {saved_name(x) or x.host} - użyj "
                                  "„Zmień kartę” w tabeli użytkowników (stara karta straci wtedy dostęp)")
    with db() as con:
        _card_link(con, current_controller(), ko, kn, _login_now())
    return {"ok": True, "msg": f"Karta {ko} połączona z kartą {kn} - czas pracy i „kto w środku” liczą je razem",
            **people_directory()}


def card_candidates(name, card=""):
    """Osoby o tej samej nazwie z innym numerem karty - do pytania „czy to wymiana karty?” przy dodawaniu."""
    n = " ".join((name or "").split()).casefold()
    k = card_key(card)
    if not n:
        return {"candidates": []}
    c = current_controller()
    cards = _cards_now(c) if c is not None else None
    with db() as con:
        alias = card_aliases(con)
        rows = [dict(r) for r in con.execute("SELECT p.card, p.name, d.name AS dept FROM people p "
                                             "LEFT JOIN departments d ON d.id = p.dept_id")]
    out = []
    for r in rows:
        if " ".join((r["name"] or "").split()).casefold() != n or r["card"] == k or r["card"] in alias:
            continue
        r["on_ctrl"] = None if cards is None else r["card"] in cards
        out.append(r)
    out.sort(key=lambda r: (not r["on_ctrl"], r["card"]))
    return {"candidates": out}


# -- kopia zapasowa użytkowników z działami --
# Plik JSON: działy panelu (także puste) z kartami i nazwami użytkowników kontrolera + karty bez działu.
# Celowo BEZ uprawnień do drzwi, PIN-ów i godzin wejścia - zależą od tego, które drzwi są na którym
# przekaźniku, a to może się zmienić. Karta przywrócona do kontrolera dostaje dostęp do wszystkich drzwi
# (jak każda nowa karta), PIN-y ustawia potem synchronizacja godzin wejścia.
BACKUP_KIND, BACKUP_FORMAT = "acb-panel-users", 1
_RESTORE = {}               # ctrl_key -> stan przywracania
_RESTORE_LOCK = threading.Lock()


def controller_cards(c, names=True):
    """Karty zapisane w kontrolerze: {numer: nazwa}. Numery z kanału UDP (strona Users pokazuje tylko
    20 pierwszych), nazwy ze strony Users; `names=False` - same numery (nazwy puste)."""
    try:
        cards = [str(struct.unpack_from("<I", p, 0)[0]) for p in c.udp().privileges()]
    except (ControllerError, OSError) as e:
        d = c.users()
        if d["total"] > len(d["users"]):
            raise ControllerError(f"Nie odczytano listy kart kanałem UDP ({e}), a strona WWW kontrolera "
                                  f"pokazuje tylko {len(d['users'])} z {d['total']} użytkowników")
        return {k: u["name"] for u in d["users"] if (k := card_key(u["card"]))}
    _CARDS[ctrl_key(c)] = set(cards)
    found = c.card_names(cards) if names and cards else {}
    return {k: found.get(k, "") for k in cards}


def users_backup(c=None):
    c = c or require_active()
    if c.auto:
        raise ControllerError("Zakończ tryb auto-dodawania kart przed kopią zapasową")
    cards = controller_cards(c)
    with db() as con:
        con.executemany("INSERT INTO people(card, name) VALUES (?, ?) ON CONFLICT(card) "
                        "DO UPDATE SET name = excluded.name WHERE excluded.name <> ''",
                        [(k, n) for k, n in cards.items() if n])
        people = _people_map(con)
    info = active_info(c)
    groups = {d["id"]: {"name": d["name"], "users": []} for d in departments()}
    none = []
    for k in sorted(cards, key=lambda k: ((cards[k] or people.get(k, {}).get("name") or "~").lower(), int(k))):
        p = people.get(k, {})
        u = {"card": k, "name": cards[k] or p.get("name", "")}
        (groups[p["dept_id"]]["users"] if p.get("dept_id") in groups else none).append(u)
    return {"kind": BACKUP_KIND, "format": BACKUP_FORMAT, "app_version": APP_VERSION,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "controller": {"name": info["saved_name"], "model": c.model,
                           "device_no": c.info.get("device_no", ""), "host": c.host},
            "users_total": len(cards), "departments": list(groups.values()), "no_department": none}


def users_backup_file(c=None):
    data = users_backup(c)
    ctrl = data["controller"]
    # nagłówek HTTP jest w latin-1 - nazwa pliku bez polskich liter
    label = unicodedata.normalize("NFKD", (ctrl["name"] or ctrl["device_no"] or ctrl["host"])
                                  .replace("ł", "l").replace("Ł", "L")).encode("ascii", "ignore").decode()
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-") or "kontroler"
    name = f"acb-uzytkownicy_{label}_{time.strftime('%Y-%m-%d_%H%M')}.json"
    return name, json.dumps(data, ensure_ascii=False, indent=1)


def _backup_parse(raw):
    try:
        data = json.loads(raw or "")
    except ValueError:
        raise ControllerError("Plik nie jest kopią zapasową użytkowników panelu (błędny JSON)")
    if not isinstance(data, dict) or data.get("kind") != BACKUP_KIND:
        raise ControllerError("Plik nie jest kopią zapasową użytkowników panelu ACB")
    if data.get("format") != BACKUP_FORMAT:
        raise ControllerError(f"Nieobsługiwana wersja kopii ({data.get('format')}) - zaktualizuj panel")
    depts, users = [], {}

    def take(items, dept):
        if not isinstance(items, list):
            raise ControllerError("Uszkodzona kopia zapasowa (lista użytkowników)")
        for u in items:
            card = str(u.get("card", "")) if isinstance(u, dict) else ""
            if not re.fullmatch(r"\d{1,19}", card):
                raise ControllerError(f"Uszkodzona kopia zapasowa: nieprawidłowy numer karty „{card[:24]}”")
            users[card_key(card)] = {"name": str(u.get("name") or "").strip()[:32], "dept": dept}

    for d in data.get("departments") or []:
        name = _dept_name(d.get("name") if isinstance(d, dict) else "")
        if name.lower() not in {x.lower() for x in depts}:
            depts.append(name)
        take(d.get("users") or [], name)
    take(data.get("no_department") or [], None)
    ctrl = data.get("controller") if isinstance(data.get("controller"), dict) else {}
    return {"created": str(data.get("created", "")), "controller": ctrl, "departments": depts, "users": users}


def _dept_id(con, name):
    r = con.execute("SELECT id FROM departments WHERE name = ?", (name,)).fetchone()
    return r[0] if r else None


def restore_preview(raw):
    c = require_active()
    b = _backup_parse(raw)
    on_ctrl = controller_cards(c, names=False)
    with db() as con:
        people = _people_map(con)
        existing = {name for name in b["departments"] if _dept_id(con, name) is not None}
    add, moves = [], []
    for k, u in sorted(b["users"].items(), key=lambda x: ((x[1]["name"] or "~").lower(), int(x[0]))):
        p = people.get(k, {})
        if k not in on_ctrl:
            add.append({"card": k, **u})
        if (p.get("dept") or "").lower() != (u["dept"] or "").lower():
            moves.append({"card": k, "name": u["name"] or p.get("name", ""), "from": p.get("dept"), "to": u["dept"]})
    dev = str(b["controller"].get("device_no", ""))
    return {"created": b["created"], "controller": b["controller"],
            "same_controller": bool(dev) and dev == c.info.get("device_no", ""),
            "users": len(b["users"]), "present": len(b["users"]) - len(add),
            "extra": len(set(on_ctrl) - set(b["users"])),
            "departments": [{"name": n, "exists": n in existing,
                             "users": sum(u["dept"] == n for u in b["users"].values())} for n in b["departments"]],
            "add": add, "moves": moves}


def _restore_run(c, b, add_cards, set_depts, st):
    try:
        if set_depts:
            with db() as con:
                for name in b["departments"]:
                    if _dept_id(con, name) is None:
                        con.execute("INSERT INTO departments(name) VALUES (?)", (name,))
                        st["depts_created"] += 1
        if add_cards:
            present = controller_cards(c, names=False)
            todo = [(k, u) for k, u in b["users"].items() if k not in present]
            st["total"] = len(todo)
            for k, u in todo:
                if not is_connected(c):
                    raise ControllerError("przerwano - rozłączono z kontrolerem")
                st["current"] = u["name"] or f"karta {k}"
                try:
                    c.add_card(k, u["name"])
                    st["added"] += 1
                except DeviceError:
                    raise                   # kontroler nie odpowiada - kolejne karty też się nie dodadzą
                except ControllerError as e:
                    st["failed"].append({"card": k, "name": u["name"], "error": str(e)})
                st["done"] += 1
            st["current"] = ""
        with db() as con:
            for k, u in b["users"].items():
                if set_depts:
                    dept = _dept_id(con, u["dept"]) if u["dept"] else None
                    con.execute("INSERT INTO people(card, name, dept_id) VALUES (?, ?, ?) "
                                "ON CONFLICT(card) DO UPDATE SET dept_id = excluded.dept_id, "
                                "name = CASE WHEN people.name = '' THEN excluded.name ELSE people.name END",
                                (k, u["name"], dept))
                    st["assigned"] += 1
                else:
                    con.execute("INSERT INTO people(card, name) VALUES (?, ?) ON CONFLICT(card) "
                                "DO UPDATE SET name = excluded.name WHERE people.name = ''", (k, u["name"]))
        _watch_reload()
        res = entry_pins_sync(c)
        pins_sync_all(skip=c)
        if res["error"]:
            st["warning"] = f"Nie zaktualizowano PIN-ów w kontrolerze: {res['error']}"
    except Exception as e:
        st["stopped"] = str(e)
    finally:
        st["running"] = False
        st["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def restore_state():
    c = require_active()
    with _RESTORE_LOCK:
        return dict(_RESTORE.get(ctrl_key(c)) or {"running": False, "finished": None})


def restore_start(raw, add_cards, set_depts):
    c = require_active()
    if not (add_cards or set_depts):
        raise ControllerError("Zaznacz, co przywrócić: karty albo działy")
    if c.auto:
        raise ControllerError("Zakończ tryb auto-dodawania kart przed przywracaniem")
    b = _backup_parse(raw)
    with _RESTORE_LOCK:
        st = _RESTORE.get(ctrl_key(c))
        if st and st["running"]:
            raise ControllerError("Przywracanie z kopii już trwa")
        st = _RESTORE[ctrl_key(c)] = {
            "running": True, "add_cards": add_cards, "set_depts": set_depts, "total": 0, "done": 0,
            "added": 0, "current": "", "failed": [], "depts_created": 0, "assigned": 0,
            "stopped": "", "warning": "", "finished": None}
        threading.Thread(target=_restore_run, args=(c, b, add_cards, set_depts, st), daemon=True).start()
    return restore_state()


# -- masowe dodawanie kart (wklejona lista „numer karty + właściciel") --
# Nowa ekipa albo wymiana kart to kilkadziesiąt kart - po jednej przez formularz to godzina klikania.
# Panel przyjmuje listę wklejoną z arkusza (jedna osoba w wierszu) i dodaje karty po kolei: kontroler
# przyjmuje tylko pojedyncze zapytania ACT_ID_312, więc przebieg idzie w tle z podglądem postępu,
# tak samo jak przywracanie z kopii. Dział jest opcjonalny - wpisany tu oszczędza późniejsze
# przypisywanie (a gdy pracownicy trafili do panelu bez działu, robi to masowo `people_assign_bulk`).
_BULK = {}                      # ctrl_key -> stan dodawania
_BULK_LOCK = threading.Lock()
BULK_MAX = 500                  # jedno wklejenie; wyżej i tak nie przebiegłoby przed wygaśnięciem cierpliwości


def _bulk_split(line):
    """Wiersz listy -> (numer karty, nazwa właściciela). Rozdzielnik: tabulator, średnik, przecinek,
    pionowa kreska albo spacja. Numer może stać przed nazwą („123456  Jan Kowalski") albo za nią
    („Jan Kowalski;123456") - kolumny w arkuszach bywają w obu kolejnościach."""
    s = line.strip().strip("|").strip()
    if re.search(r"[;,\t|]", s):
        parts = re.split(r"\s*[;,\t|]\s*", s, maxsplit=1)
    else:
        m = re.match(r"^(\d+)\s+(\S.*)$", s) or re.match(r"^(.*?\S)\s+(\d+)$", s)
        parts = [m.group(1), m.group(2)] if m else [s]
    a = parts[0].strip().strip('"').strip()
    b = (parts[1].strip().strip('"').strip() if len(parts) > 1 else "")
    if not a.isdigit() and b.isdigit():
        a, b = b, a
    return a, b


def _bulk_parse(raw, on_ctrl):
    """Wklejona lista -> wiersze z rozpoznanym stanem: `new` (do dodania), `present` (karta już jest
    w kontrolerze - z listy bierze tylko dział, bo nazwę i tak nadpisuje ta z kontrolera),
    `dup` (powtórka w liście), `error`."""
    rows, seen = [], set()
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        num, name = _bulk_split(s)
        k = card_key(num)
        row = {"line": s[:120], "card": k, "name": AcbController._clip(name), "status": "new", "note": ""}
        if not num or not num.isdigit() or len(num) > 19:
            row.update(card="", status="error", note="nie znaleziono numeru karty w tym wierszu")
        elif not k or k == "0":
            row.update(status="error", note="numer karty 0 - kontroler takiej karty nie zapisze")
        elif k in seen:
            row.update(status="dup", note="ten numer jest w liście więcej niż raz - karta zostanie dodana raz")
        elif k in on_ctrl:
            row.update(status="present", note="karta jest już w kontrolerze - jej nazwa w kontrolerze zostaje "
                                                "bez zmian, panel ustawi tylko dział")
        else:
            row["note"] = card_warning(k) or ""
        if k and row["status"] != "dup":
            seen.add(k)
        rows.append(row)
    if len(rows) > BULK_MAX:
        raise ControllerError(f"Lista ma {len(rows)} wierszy - naraz można dodać najwyżej {BULK_MAX}")
    return rows


def _bulk_counts(rows):
    return {k: sum(r["status"] == k for r in rows) for k in ("new", "present", "dup", "error")}


def bulk_add_preview(raw):
    c = require_active()
    rows = _bulk_parse(raw, controller_cards(c, names=False))
    if not rows:
        raise ControllerError("Lista jest pusta - wklej po jednej osobie w wierszu, np. „123456  Jan Kowalski”")
    return {"ok": True, "rows": rows, "departments": departments(), "counts": _bulk_counts(rows)}


def _bulk_run(c, rows, dept, valid_to, st):
    try:
        for r in rows:
            if not is_connected(c):
                raise ControllerError("przerwano - rozłączono z kontrolerem")
            st["current"] = r["name"] or f"karta {r['card']}"
            if r["status"] == "new":
                try:
                    c.add_card(r["card"], r["name"])
                    st["added"] += 1
                except DeviceError:
                    raise               # kontroler nie odpowiada - kolejne karty też się nie dodadzą
                except ControllerError as e:
                    st["failed"].append({"card": r["card"], "name": r["name"], "error": str(e)})
                    st["done"] += 1
                    continue
                if valid_to:
                    try:
                        card_validity_on(c, r["card"], "", valid_to)
                    except (ControllerError, OSError) as e:
                        st["failed"].append({"card": r["card"], "name": r["name"],
                                             "error": f"dodana, ale bez daty ważności ({e})"})
            with db() as con:
                con.execute("INSERT INTO people(card, name) VALUES (?, ?) ON CONFLICT(card) DO UPDATE SET "
                            "name = CASE WHEN excluded.name <> '' THEN excluded.name ELSE people.name END",
                            (r["card"], r["name"]))
                if dept is not None:
                    con.execute("UPDATE people SET dept_id = ? WHERE card = ?", (dept, r["card"]))
                    st["assigned"] += 1
            st["done"] += 1
        st["current"] = ""
        _watch_reload()
        res = entry_pins_sync(c)
        pins_sync_all(skip=c)
        if res["error"]:
            st["warning"] = f"Nie zaktualizowano PIN-ów w kontrolerze: {res['error']}"
    except Exception as e:
        st["stopped"] = str(e)
    finally:
        st["running"] = False
        st["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def bulk_add_state():
    c = require_active()
    with _BULK_LOCK:
        return dict(_BULK.get(ctrl_key(c)) or {"running": False, "finished": None})


def bulk_add_start(raw, dept_id, valid_to):
    c = require_active()
    if c.auto:
        raise ControllerError("Zakończ tryb auto-dodawania kart przed dodawaniem listy")
    dept = int(dept_id) if str(dept_id or "").strip() else None
    if dept is not None:
        with db() as con:
            if not con.execute("SELECT 1 FROM departments WHERE id = ?", (dept,)).fetchone():
                raise ControllerError("Nie znaleziono działu")
    if valid_to:
        _iso_day(valid_to, "data „ważna do”")
    rows = [r for r in _bulk_parse(raw, controller_cards(c, names=False)) if r["status"] in ("new", "present")]
    if not rows:
        raise ControllerError("Nie ma czego dodać - w liście nie ma ani jednego poprawnego numeru karty")
    with _BULK_LOCK:
        st = _BULK.get(ctrl_key(c))
        if st and st["running"]:
            raise ControllerError("Dodawanie listy kart już trwa")
        st = _BULK[ctrl_key(c)] = {
            "running": True, "total": len(rows), "done": 0, "added": 0, "assigned": 0, "current": "",
            "failed": [], "dept": _dept_name_by_id(dept), "valid_to": valid_to,
            "stopped": "", "warning": "", "finished": None}
        threading.Thread(target=_bulk_run, args=(c, rows, dept, valid_to, st), daemon=True).start()
    return bulk_add_state()


def _dept_name_by_id(dept):
    if dept is None:
        return ""
    with db() as con:
        r = con.execute("SELECT name FROM departments WHERE id = ?", (dept,)).fetchone()
    return r[0] if r else ""


def people_assign_bulk(cards, dept_id):
    """Przypisanie zaznaczonych kart do jednego działu naraz. Działy są tylko w panelu, więc to zapis
    w bazie - kontroler dostaje najwyżej nowe PIN-y godzin wejścia, raz na całą paczkę."""
    keys = list(dict.fromkeys(k for k in (card_key(x) for x in re.split(r"[,;\s]+", cards or "")) if k))
    if not keys:
        raise ControllerError("Nie zaznaczono żadnej karty")
    dept = int(dept_id) if str(dept_id or "").strip() else None
    with db() as con:
        if dept is not None and not con.execute("SELECT 1 FROM departments WHERE id = ?", (dept,)).fetchone():
            raise ControllerError("Nie znaleziono działu")
        con.executemany("INSERT INTO people(card, name, dept_id) VALUES (?, '', ?) "
                        "ON CONFLICT(card) DO UPDATE SET dept_id = excluded.dept_id",
                        [(k, dept) for k in keys])
    _watch_reload()
    name = _dept_name_by_id(dept)
    out = {"ok": True, "departments": departments(), "count": len(keys), "dept": name,
           "msg": f"Przypisano {len(keys)} os. do działu „{name}”" if dept is not None
                  else f"{len(keys)} os. bez działu"}
    c = current_controller()
    if c is not None:
        res = entry_pins_sync(c)
        if res["error"]:
            out["warning"] = f"Nie zaktualizowano PIN-ów w kontrolerze: {res['error']}"
        elif res["changed"]:
            out["pins"] = res["changed"]
    pins_sync_all(skip=c)
    return out


# -- drzwi liczące czas pracy --
# -- godziny wejścia: konfiguracja w panelu (kontroler nie oddaje listy zadań) --
def _dept_ids():
    with db() as con:
        return [r[0] for r in con.execute("SELECT id FROM departments")]


def _entry_cfg(c, column="applied"):
    """Konfiguracja kontrolera z bazy: `applied` - zapisana na kontrolerze (według niej panel przełącza
    PIN-y), `config` - ostatnio edytowana. Uszkodzona albo brak = bez ograniczeń."""
    with db() as con:
        r = con.execute(f"SELECT {column} FROM entry_hours WHERE ctrl = ?", (ctrl_key(c),)).fetchone()
    try:
        return entry_hours_normalize(json.loads(r[0]) if r and r[0] else {}, c.doors, _dept_ids())
    except (ValueError, ControllerError):
        return entry_hours_normalize({}, c.doors, [])


def _card_groups():
    """Numer karty -> klucz grupy (id działu albo NODEPT); karty spoza bazy panelu to NODEPT."""
    with db() as con:
        return {r[0]: str(r[1]) if r[1] is not None else NODEPT
                for r in con.execute("SELECT card, dept_id FROM people")}


def entry_hours_state(fresh=False):
    c = require_active()
    key = ctrl_key(c)
    if fresh or key not in _CARDS:
        try:
            _CARDS[key] = {str(struct.unpack_from("<I", p, 0)[0]) for p in c.udp().privileges()}
        except Exception as e:
            _devlog(f"Lista kart z kontrolera (godziny wejścia) błąd: {e}")
    on_ctrl = _CARDS.get(key)
    with db() as con:
        row = con.execute("SELECT applied_at, error FROM entry_hours WHERE ctrl = ?", (key,)).fetchone()
        known = {p["card"]: p for p in con.execute("SELECT card, name, dept_id FROM people")}
        passes = [dict(p) for p in con.execute(
            "SELECT e.time, e.card, e.door, e.result, COALESCE(p.name, '') AS name FROM entry_passes e "
            "LEFT JOIN people p ON p.card = e.card WHERE e.ctrl = ? ORDER BY e.time DESC LIMIT 5", (key,))]
    cfg, applied = _entry_cfg(c, "config"), _entry_cfg(c)
    names = {d["n"]: d["name"] for d in c.info.get("doors_list", [])}
    watch = _watch_state(key)
    now = datetime.datetime.now() + datetime.timedelta(seconds=watch.get("offset", 0))
    # liczba kart w grupach: karty zapisane w kontrolerze (baza panelu pamięta też usunięte - dla logu)
    cards = on_ctrl if on_ctrl is not None else set(known)
    count = {}
    for card in cards:
        g = str(known[card]["dept_id"]) if card in known and known[card]["dept_id"] is not None else NODEPT
        count[g] = count.get(g, 0) + 1
    nodept = sorted((known[k]["name"] if k in known and known[k]["name"] else f"karta {k}")
                    for k in cards if k not in known or known[k]["dept_id"] is None)
    groups = [dict(cfg["groups"][str(d["id"])], key=str(d["id"]), name=d["name"], cards=count.get(str(d["id"]), 0))
              for d in departments()]
    groups.append(dict(cfg["groups"][NODEPT], key=NODEPT, name="Pracownicy bez działu",
                       cards=count.get(NODEPT, 0), people=nodept))
    for g in groups:
        g["now"] = group_allows(applied["groups"][g["key"]], now, applied["holidays"])
    return {"doors": [{"n": n, "name": names.get(n, ""), "enabled": cfg["doors"][str(n)]}
                      for n in range(1, c.doors + 1)],
            "groups": groups, "clock": now.strftime("%H:%M"), "restricted": any(applied["doors"].values()),
            "plan": _stored_plan(c),
            "applied_at": row["applied_at"] if row else "", "pending": cfg != applied,
            "error": row["error"] if row else "", "verified": c.doors == 2,
            "people_checked": on_ctrl is not None,
            "holidays": cfg["holidays"], "holiday_today": holiday_on(applied["holidays"], now.date()),
            "watch": {k: v for k, v in watch.items() if k not in ("offset", "reload")}, "passes": passes,
            "pins": _PINS.get(key),
            # harmonogram wielozmianowy zapisany wcześniej w trybie online: w offline nikt nie przełącza PIN-ów
            "offline_stale": bool(OFFLINE and (_stored_plan(c) or {}).get("kind") == "multi")}


# -- PIN karty w pamięci kontrolera: PIN 0 = wchodzi -----------------------------
# W trybie „karta + PIN na wejściu” kontroler nie pyta o PIN kart z PIN-em 0 (tak jak symulator
# uhppoted). Test na ACB-002 2026-09-17 10:55: karta z PIN-em 0 weszła przy zablokowanym wejściu,
# karta z PIN-em 345678 - odmowa kodem 7. Karty grup, które w tej chwili mogą wchodzić, dostają
# PIN 0, pozostałe karty z PIN-em 0 wracają do 345678 (domyślny PIN kart dodanych przez stronę WWW).
# Karty z innym PIN-em panel zostawia - nie wejdą nigdy (chyba że czytnik ma klawiaturę).
ENTRY_FREE_PIN, DEFAULT_PIN = 0, 345678
_PINS = {}                  # ctrl_key -> wynik ostatniej synchronizacji
_CARDS = {}                 # ctrl_key -> numery kart zapisanych w kontrolerze (z ostatniego odczytu)
_PINS_LOCK = threading.Lock()


def _stored_plan(c):
    with db() as con:
        r = con.execute("SELECT plan FROM entry_hours WHERE ctrl = ?", (ctrl_key(c),)).fetchone()
    try:
        return json.loads(r[0]) if r and r[0] else None
    except ValueError:
        return None


def entry_plan_for(c, cfg):
    """Plan, jaki dałaby ta konfiguracja przy kartach zapisanych w kontrolerze - bez zmieniania czegokolwiek.
    Używane w trybie offline, żeby odrzucić zapis kilku zmian ZANIM cokolwiek trafi do bazy i na kontroler."""
    key = ctrl_key(c)
    cards = _CARDS.get(key)
    if cards is None:
        cards = _CARDS[key] = {str(struct.unpack_from("<I", p, 0)[0]) for p in c.udp().privileges()}
    groups = _card_groups()
    return entry_plan(cfg, {groups.get(card, NODEPT) for card in cards})


def offline_shift_error(plan):
    """Komunikat, gdy plan wymaga stale połączonego panelu (kilka zmian), a panel działa w trybie offline."""
    if not OFFLINE or plan.get("kind") != "multi":
        return ""
    return ("Tryb offline nie obsługuje kilku zmian. Przy różnych godzinach dla różnych działów (albo gdy "
            "któraś grupa ma „brak wejścia”) drzwi zostają stale w trybie z PIN-em, a wejścia otwiera panel, "
            "przełączając PIN-y kart - to działa tylko wtedy, gdy panel jest połączony bez przerwy. "
            "Ustaw wszystkim grupom z kartami te same godziny (albo „o każdej porze”) - taki harmonogram "
            "zapisuje się w liście zadań kontrolera i działa także po zamknięciu panelu. "
            "Kilka zmian wymaga trybu online.")


def entry_pins_sync(c, cfg=None, force_tasks=False):
    """Ustawia PIN-y kart według planu i godzin grup w chwili zegara kontrolera. `cfg` - konfiguracja
    do zastosowania (domyślnie zapisana na kontrolerze). Gdy plan wynikający z kart w kontrolerze różni
    się od zapisanego (np. pracownik trafił do działu z innymi godzinami), zapisuje też listę zadań -
    najpierw PIN-y, potem tryb drzwi. `force_tasks` - zapis listy zadań zawsze (zapis konfiguracji)."""
    key = ctrl_key(c)
    stored = cfg is None
    res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "cards": 0, "free": 0, "changed": [], "error": "",
           "groups": [], "plan": None, "tasks": None}
    with _PINS_LOCK:
        try:
            cfg = cfg or _entry_cfg(c)
            wg = c.udp()
            if any(cfg["doors"].values()):
                groups = _card_groups()
                with db() as con:
                    names = {r[0]: r[1] for r in con.execute("SELECT card, name FROM people")}
                privs = wg.privileges()
                res["cards"] = len(privs)
                cards = [str(struct.unpack_from("<I", p, 0)[0]) for p in privs]
                _CARDS[key] = set(cards)
                plan = entry_plan(cfg, {groups.get(card, NODEPT) for card in cards})
                now = wg.clock(quiet=True)
                if force_tasks or (stored and plan != _stored_plan(c)):
                    entry_tasks_fit(cfg, plan, now)     # zanim ruszymy PIN-y kart
                allowed = free_groups(cfg, plan, now)
                res["groups"] = sorted(allowed)
                for card, priv in zip(cards, privs):
                    pin = int.from_bytes(priv[16:19], "little")
                    free = groups.get(card, NODEPT) in allowed
                    want = ENTRY_FREE_PIN if free else (DEFAULT_PIN if pin == ENTRY_FREE_PIN else pin)
                    res["free"] += free
                    if want != pin:
                        wg.set_pin(priv, want)
                        res["changed"].append({"card": card, "name": names.get(card, ""), "pin": want})
                        _devlog(f"PIN karty {card} ({names.get(card, '')}): {pin} -> {want}")
            else:
                plan = PLAN_OFF
                res["skipped"] = True
            res["plan"] = plan
            if force_tasks or (stored and plan != _stored_plan(c)):
                res["tasks"] = c.apply_entry_hours(cfg, plan)
                _devlog(f"Lista zadań kontrolera zapisana: plan {plan}, zadań {res['tasks']['tasks']}")
                if stored:
                    with db() as con:
                        con.execute("UPDATE entry_hours SET plan = ? WHERE ctrl = ?", (json.dumps(plan), key))
                    _watch_reload(key)
        except Exception as e:
            res["error"] = str(e)
            _devlog(f"PIN synchronizacja błąd: {e}")
        _PINS[key] = res
    return res


# -- przełączanie PIN-ów o godzinach grup + zapasowe otwieranie ------------------
# Wątek co 0,2 s liczy (zegarem kontrolera), które grupy mogą teraz wchodzić; gdy zbiór się zmieni
# (początek / koniec okna działu), po połączeniu i co 10 min synchronizuje PIN-y. Zapasowo, gdyby
# PIN karty się rozjechał, czyta stan kontrolera (UDP 0x20), a gdy karta z grupy mogącej wejść
# zostanie odrzucona na czytniku WEJŚCIA z kodem 7 (brak PIN-u), otwiera drzwi zdalnie (0x40).
# Firmware może sprawdzać PIN PRZED uprawnieniem do drzwi (tak robi symulator uhppoted), więc przed
# otwarciem panel sam czyta uprawnienie karty (0x5A) - otwiera tylko drzwi z dostępem „zawsze” (1).
WATCH_POLL = 0.2
PINS_RESYNC = 600
PINS_RETRY = 30             # po błędzie synchronizacji
WATCH_MAX_AGE = 30          # starszej odmowy (np. sprzed przerwy w łączności) nie otwieramy
WG_REASON_NO_PIN = 7
_WATCH = {}                 # ctrl_key -> stan przełączania: state, msg, since, offset, reload


def _watch_state(key):
    return _WATCH.setdefault(key, {"state": "off", "msg": "Panel nie jest połączony z kontrolerem", "reload": True})


def _watch_reload(key=None):
    """Konfiguracja albo działy się zmieniły - wątki przełączania przeczytają je ponownie."""
    for k in [key] if key else list(_WATCH):
        _watch_state(k)["reload"] = True


def pins_sync_all(skip=None):
    """PIN-y na wszystkich połączonych kontrolerach (działy i pracownicy są wspólni) - w tle."""
    _watch_reload()
    for c in connected():
        if c is not skip:
            threading.Thread(target=entry_pins_sync, args=(c,), daemon=True).start()


def _watch_set(key, state, msg):
    w = _watch_state(key)
    if (w.get("state"), w.get("msg")) != (state, msg):
        w.update(state=state, msg=msg, since=time.strftime("%Y-%m-%d %H:%M:%S"))
        _devlog(f"WATCH {key} {state}: {msg}")


def _watch_pass(c, wg, cfg, plan, groups, ev, offset):
    if not (ev["type"] == WG_EVENT_SWIPE and not ev["granted"] and ev["reason"] == WG_REASON_NO_PIN
            and ev["dir"] == WG_DIR_IN and cfg["doors"].get(str(ev["door"])) and ev["time"] is not None
            and groups.get(card_key(ev["card"]), NODEPT) in free_groups(cfg, plan, ev["time"])):
        return
    age = (datetime.datetime.now() + offset - ev["time"]).total_seconds()
    if age > WATCH_MAX_AGE:
        _devlog(f"WATCH pominięto starą odmowę karty {ev['card']} (#{ev['door']}, {age:.0f} s temu)")
        return
    access = wg.card_doors(ev["card"])[ev["door"] - 1] if 1 <= ev["door"] <= 4 else 0
    if access != 1:
        _devlog(f"WATCH karta {ev['card']} bez stałego dostępu do drzwi #{ev['door']} (bajt {access}) - nie otwieram")
        return
    try:
        wg.open_door(ev["door"])
        result = "udp"
    except ControllerError as e:
        _devlog(f"WATCH otwarcie UDP nieudane ({e}) - próba przez stronę WWW")
        try:
            c.open_door(ev["door"])
            result = "www"
        except ControllerError as e2:
            result = f"błąd: {e2}"
    _devlog(f"WATCH karta {ev['card']} drzwi #{ev['door']} rekord {ev['record']}: {result} ({age:.1f} s)")
    with db() as con:
        con.execute("INSERT OR IGNORE INTO entry_passes(ctrl, time, card, door, record, result) "
                    "VALUES (?, ?, ?, ?, ?, ?)", (ctrl_key(c), ev["time"].strftime("%Y-%m-%d %H:%M:%S"),
                                                   card_key(ev["card"]), ev["door"], ev["record"], result))


def _watch_loop(c):
    key = ctrl_key(c)
    watch = _watch_state(key)
    watch["reload"] = True
    last, offset, clock_at, cfg_at, cfg, groups, plan = None, None, 0, 0, None, {}, PLAN_MULTI
    pins_at, pins_allowed, pins_err = None, None, False
    names = {}
    while is_connected(c):
        time.sleep(WATCH_POLL)
        now = time.monotonic()
        try:
            if watch.pop("reload", False) or now - cfg_at > 10:
                cfg, groups, plan = _entry_cfg(c), _card_groups(), _stored_plan(c) or PLAN_MULTI
                names = {str(d["id"]): d["name"] for d in departments()}
                names[NODEPT] = "bez działu"
                cfg_at = now
            doors = [n for n, on in cfg["doors"].items() if on]
            if not doors:
                last, pins_allowed = None, None
                _watch_set(key, "idle", "Nieaktywny - żadne drzwi nie mają ograniczenia wejścia")
                time.sleep(1.5)
                continue
            wg = c.udp()
            if offset is None or now - clock_at > 600:
                offset = wg.clock(quiet=True) - datetime.datetime.now()
                watch["offset"] = offset.total_seconds()
                clock_at = now
            allowed = free_groups(cfg, plan, datetime.datetime.now() + offset)
            if (pins_at is None or allowed != pins_allowed
                    or now - pins_at > (PINS_RETRY if pins_err else PINS_RESYNC)):
                res = entry_pins_sync(c)
                pins_at, pins_err = now, bool(res["error"])
                pins_allowed = allowed if pins_err else frozenset(res["groups"])
                if pins_allowed != allowed:
                    offset = None           # zegar kontrolera uciekł od przesunięcia - odczytaj go ponownie
                    continue
            ev = wg.last_event()
            if last is None or ev["record"] < last:        # start albo wyczyszczony log kontrolera
                last = ev["record"]
            elif ev["record"] > last:
                evs = [wg.event(i) for i in range(max(last + 1, ev["record"] - 9), ev["record"])] + [ev]
                last = ev["record"]
                for e in evs:
                    _watch_pass(c, wg, cfg, plan, groups, e, offset)
            if plan.get("kind") == "single":
                _watch_set(key, "active", "Jedna zmiana - godziny drzwi " + ", ".join(f"#{n}" for n in doors)
                           + " przełącza kontroler; panel pilnuje zmian w działach i kart")
            else:
                _watch_set(key, "active", "Kilka zmian - panel przełącza drzwi " + ", ".join(f"#{n}" for n in doors)
                           + "; teraz wchodzą: " + (", ".join(sorted(names.get(k, k) for k in allowed)) or "nikt"))
        except Exception as e:
            offset = None
            _watch_set(key, "error", f"Brak kontaktu z kontrolerem: {e}")
            time.sleep(3)
    if _WATCH.get(key) is watch and ctrl_key(c) not in CONNS:
        _watch_set(key, "off", "Panel nie jest połączony z kontrolerem")


def entry_hours_save(raw):
    c = require_active()
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        raise ControllerError("Nieprawidłowe dane godzin wejścia")
    cfg = entry_hours_normalize(data, c.doors, _dept_ids())
    if OFFLINE:
        err = offline_shift_error(entry_plan_for(c, cfg))
        if err:
            raise ControllerError(err)
    text = json.dumps(cfg, sort_keys=True)
    key = ctrl_key(c)
    with db() as con:
        con.execute("INSERT INTO entry_hours(ctrl, config) VALUES (?, ?) "
                    "ON CONFLICT(ctrl) DO UPDATE SET config = excluded.config", (key, text))
    try:
        # najpierw PIN-y, potem tryb drzwi - grupa w swoich godzinach nie traci wejścia ani na chwilę
        pins = entry_pins_sync(c, cfg, force_tasks=True)
        if pins["error"]:
            raise ControllerError(pins["error"])
        res = pins["tasks"]
    except Exception as e:
        with db() as con:
            con.execute("UPDATE entry_hours SET error = ? WHERE ctrl = ?", (str(e), key))
        _watch_reload(key)
        raise ControllerError(f"Zapisano w panelu, ale nie na kontrolerze: {e}")
    with db() as con:
        con.execute("UPDATE entry_hours SET applied = config, applied_at = ?, error = '', plan = ? WHERE ctrl = ?",
                    (time.strftime("%Y-%m-%d %H:%M:%S"), json.dumps(pins["plan"]), key))
    _watch_reload(key)
    kind = pins["plan"]["kind"]
    st = entry_hours_state()
    st.update(ok=True, msg=f"Zapisano na kontrolerze ({res['tasks']} zadań, zegar kontrolera {res['clock'][11:16]})"
              + {"single": " - jedna zmiana: działa bez połączonego panelu",
                 "multi": f" - kilka zmian: panel musi być stale połączony (PIN 0 teraz: kart {pins['free']})"}.get(kind, ""))
    return st


def tracking_supported(c):
    """Czy drzwi mają osobny czytnik wejścia i wyjścia (ACB-001, ACB-002). Bez tego czas pracy liczy się
    z par drzwi - patrz door_roles."""
    return bool(MODELS.get(c.doors, {}).get("inout"))


def roles_mode(c):
    return not tracking_supported(c)


def door_roles(c):
    """Drzwi wejścia / wyjścia na kontrolerze z jednym czytnikiem na drzwi: {nr drzwi: 'in' | 'out'}.
    Na kontrolerze z czytnikami wejścia i wyjścia - pusty słownik (kierunek podaje sam czytnik)."""
    if not roles_mode(c):
        return {}
    with db() as con:
        return {r[0]: r[1] for r in con.execute("SELECT door, role FROM door_tracking WHERE ctrl = ?", (ctrl_key(c),))
                if 1 <= r[0] <= c.doors and r[1] in ("in", "out")}


def tracking_reason(c):
    """Dlaczego nie da się liczyć czasu pracy (pusty tekst = da się)."""
    if not roles_mode(c):
        return "" if tracked_doors(c) else "Żadne drzwi nie liczą czasu pracy - zaznacz je w zakładce „Drzwi”."
    roles = set(door_roles(c).values())
    if roles == {"in", "out"}:
        return ""
    return ("Ten kontroler ma przy drzwiach tylko czytnik wejścia - wskaż w zakładce „Drzwi”, które drzwi są "
            "wejściem, a które wyjściem (" + ("brakuje drzwi wyjścia" if roles == {"in"} else
                                              "brakuje drzwi wejścia" if roles == {"out"} else "nie wybrano żadnych") + ").")


def tracked_doors(c):
    if roles_mode(c):
        return sorted(door_roles(c))
    with db() as con:
        return sorted(r[0] for r in con.execute("SELECT door FROM door_tracking WHERE ctrl = ?",
                                                (ctrl_key(c),)) if 1 <= r[0] <= c.doors)


def reader_sql(roles, door_col="s.door", reader_col="s.reader"):
    """Wyrażenie SQL z kierunkiem odbicia: rola drzwi (pary drzwi), a dla drzwi bez roli czytnik z logu.
    Wartości w CASE to liczby i stałe 'in'/'out' z door_roles - bez danych od użytkownika."""
    if not roles:
        return reader_col
    return "CASE " + door_col + "".join(f" WHEN {int(d)} THEN '{'out' if r == 'out' else 'in'}'"
                                        for d, r in sorted(roles.items())) + f" ELSE {reader_col} END"


def tracking_state():
    c = require_active()
    roles = door_roles(c)
    on = set(tracked_doors(c))
    names = {d["n"]: d["name"] for d in c.info.get("doors_list", [])}
    reason = tracking_reason(c)
    return {"supported": True, "mode": "roles" if roles_mode(c) else "readers", "ready": not reason,
            "reason": reason,
            "doors": [{"n": n, "name": names.get(n, ""), "enabled": n in on, "role": roles.get(n, "")}
                      for n in range(1, c.doors + 1)]}


def tracking_set(door, enabled, role=None):
    c = require_active()
    door = c._door(door)
    if roles_mode(c) and role is None:
        role = "in" if enabled else ""
    if role not in (None, "", "in", "out"):
        raise ControllerError("Nieprawidłowa rola drzwi")
    if role is not None and not roles_mode(c) and role:
        raise ControllerError("Te drzwi mają czytnik wejścia i wyjścia - wystarczy włączyć analizę czasu pracy")
    with db() as con:
        if role is not None and role:
            con.execute("INSERT INTO door_tracking(ctrl, door, role) VALUES (?, ?, ?) "
                        "ON CONFLICT(ctrl, door) DO UPDATE SET role = excluded.role", (ctrl_key(c), door, role))
        elif role is None and enabled:
            con.execute("INSERT OR IGNORE INTO door_tracking(ctrl, door) VALUES (?, ?)", (ctrl_key(c), door))
        else:
            con.execute("DELETE FROM door_tracking WHERE ctrl = ? AND door = ?", (ctrl_key(c), door))
    return tracking_state()


# -- kopia logu przejść --
_SYNC = {}                  # ctrl_key -> stan pobierania
_SYNC_LOCK = threading.Lock()


def swipe_card(r):
    """Numer karty wpisu logu. Przy „Remote Open” kontroler wpisuje w pole karty adres IP, z którego
    przyszło otwarcie (192.168.1.50 -> 3232235826) - to nie karta, więc zapisujemy pustą."""
    return "" if r["status"].startswith("Remote Open") else card_key(r["card"])


def _store_swipes(key, rows):
    with db() as con:
        r = con.execute("SELECT cleared_to FROM sync_state WHERE ctrl = ?", (key,)).fetchone()
        if r and r[0]:
            # administrator wyczyścił log do tej chwili: tych wpisów nie przywracamy z kontrolera
            rows = [x for x in rows if x["time"] > r[0]]
        before = con.total_changes
        con.executemany(
            "INSERT OR IGNORE INTO swipes(ctrl, record, time, card, name, door, reader, granted, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(key, int(r["record"]), r["time"], swipe_card(r), r["name"], r["door"],
              r["reader"], int(r["granted"]), r["status"]) for r in rows])
        return con.total_changes - before


REASON_FILL_MAX = 300       # rekordów odczytywanych po UDP na jedno pobranie logu (reszta następnym razem)


def _fill_reasons(c, key):
    """Uzupełnia kod powodu odmów w kopii logu. Strona WWW kontrolera pokazuje tylko „Denied”, a kod
    (6 brak uprawnienia, 7 brak PIN-u, 15 poza godzinami/ważnością…) ma rekord UDP o tym samym numerze.
    Najpierw z podglądu na żywo (live_events), potem odczytem 0xB0 - z kontrolą czasu i karty, bo po
    przepełnieniu logu numer rekordu mógłby wskazywać inne zdarzenie."""
    with db() as con:
        con.execute("UPDATE swipes SET reason = (SELECT l.reason FROM live_events l WHERE l.ctrl = swipes.ctrl "
                    "AND l.record = swipes.record AND l.time = swipes.time) "
                    "WHERE ctrl = ? AND granted = 0 AND card <> '' AND reason IS NULL", (key,))
        todo = con.execute("SELECT record, time, card FROM swipes WHERE ctrl = ? AND granted = 0 AND card <> '' "
                           "AND reason IS NULL ORDER BY time DESC LIMIT ?", (key, REASON_FILL_MAX)).fetchall()
    if not todo:
        return
    found = []
    try:
        wg = c.udp()
        for r in todo:
            ev = wg.event(int(r["record"]))
            ok = (ev["time"] is not None and ev["time"].strftime("%Y-%m-%d %H:%M:%S") == r["time"]
                  and card_key(ev["card"]) == r["card"])
            found.append((ev["reason"] if ok else 0, r["record"], r["time"]))
    except (ControllerError, OSError) as e:
        _devlog(f"Kody powodu odmów przez UDP - błąd: {e}")     # reszta zostaje NULL, spróbujemy przy kolejnym
    if found:
        with db() as con:
            con.executemany("UPDATE swipes SET reason = ? WHERE ctrl = ? AND record = ? AND time = ?",
                            [(reason, key, rec, t) for reason, rec, t in found])


_CARDS_NOW = {}             # ctrl_key -> (czas odczytu, numery kart w kontrolerze) - do opisu odmów w logu
CARDS_NOW_AGE = 60


def _cards_now(c, max_age=CARDS_NOW_AGE):
    """Numery kart zapisanych teraz w kontrolerze (UDP, pamiętane max_age s) albo None, gdy odczyt się nie udał."""
    key = ctrl_key(c)
    hit = _CARDS_NOW.get(key)
    if hit and time.time() - hit[0] < max_age:
        return hit[1]
    try:
        cards = {str(struct.unpack_from("<I", p, 0)[0]) for p in c.udp().privileges()}
    except (ControllerError, OSError) as e:
        _devlog(f"Lista kart z kontrolera (opis odmów) błąd: {e}")
        return None
    _CARDS_NOW[key] = (time.time(), cards)
    _CARDS[key] = set(cards)
    return cards


# odmowy, przy których karta nieobecna w kontrolerze tłumaczy sprawę (kod 6 ten firmware daje też nieznanej karcie)
DENY_NOT_STORED = {6, WG_REASON_UNKNOWN_CARD}
NOT_STORED_TEXT = "karta nie jest zapisana w tym kontrolerze"


def deny_text(reason, on_ctrl):
    """Opis odmowy dla logu: kod powodu z kontrolera + czy karta jest teraz w kontrolerze (None = nie wiadomo)."""
    if on_ctrl is False and (reason in DENY_NOT_STORED or not reason):
        return NOT_STORED_TEXT
    if reason:
        return WG_REASONS.get(reason, f"kod {reason}")
    return ""


def _sync_run(c, key, st):
    try:
        with db() as con:
            r = con.execute("SELECT full_done FROM sync_state WHERE ctrl = ?", (key,)).fetchone()
        # dopóki cały log nie został raz pobrany do końca, nie przerywamy na znanych wpisach
        # (poprzednie pobieranie mogło zostać przerwane w połowie historii)
        full = bool(r and r[0])
        after = None
        while True:
            if not is_connected(c):
                raise ControllerError("przerwano - rozłączono z kontrolerem")
            chunk = c.swipe_chunk(after)
            done = not chunk
            for p in chunk:
                added = _store_swipes(key, p["rows"])
                st["added"] += added
                st["page"], st["pages"] = p["page"], p["pages"]
                if p["page"] >= p["pages"]:
                    with db() as con:
                        con.execute("INSERT INTO sync_state(ctrl, full_done) VALUES (?, 1) "
                                    "ON CONFLICT(ctrl) DO UPDATE SET full_done = 1", (key,))
                    done = True
                    break
                if full and added < len(p["rows"]):
                    done = True             # dalej są już tylko wpisy pobrane wcześniej
                    break
            if done:
                break
            after = chunk[-1]
        _fill_reasons(c, key)
    except Exception as e:
        st["error"] = str(e)
    finally:
        st["running"] = False
        st["finished"] = time.time()


def _sync_public(key):
    with _SYNC_LOCK:
        st = dict(_SYNC.get(key) or {"running": False, "added": 0, "page": 0, "pages": 0,
                                     "error": "", "finished": None})
    with db() as con:
        r = con.execute("SELECT COUNT(*), MAX(time) FROM swipes WHERE ctrl = ?", (key,)).fetchone()
    st.update(stored=r[0], newest=r[1] or "")
    return st


def swipe_sync_start(c=None):
    c = c or require_active()
    key = ctrl_key(c)
    with _SYNC_LOCK:
        st = _SYNC.get(key)
        if not (st and st["running"]):
            if c.auto:
                raise ControllerError("Zakończ tryb auto-dodawania kart przed pobraniem logu")
            st = _SYNC[key] = {"running": True, "added": 0, "page": 0, "pages": 0,
                               "error": "", "finished": None}
            threading.Thread(target=_sync_run, args=(c, key, st), daemon=True).start()
    return _sync_public(key)


def _log_filters(key, card="", dept="", day_from="", day_to=""):
    where, args = ["s.ctrl = ?"], [key]
    if card_key(card):
        with db() as con:
            group = card_group(con, card_key(card))
        where.append(f"s.card IN ({','.join('?' * len(group))})")
        args.extend(group)
    if dept == "none":
        where.append("s.card <> '' AND s.card NOT IN (SELECT card FROM people WHERE dept_id IS NOT NULL)")
    elif str(dept or "").isdigit():
        where.append("s.card IN (SELECT card FROM people WHERE dept_id = ?)")
        args.append(int(dept))
    if _day(day_from):
        where.append("s.time >= ?")
        args.append(f"{_day(day_from).isoformat()} 00:00:00")
    if _day(day_to):
        where.append("s.time <= ?")
        args.append(f"{_day(day_to).isoformat()} 23:59:59")
    return " AND ".join(where), args


# odmowa wejścia, po której panel otworzył drzwi (wyjątek od godzin wejścia)
PASSED_SQL = ("EXISTS(SELECT 1 FROM entry_passes e WHERE e.ctrl = s.ctrl AND e.card = s.card "
              "AND e.time = s.time AND e.door = s.door AND e.result IN ('udp', 'www'))")


def log_local(q):
    c = require_active()
    key = ctrl_key(c)
    where, args = _log_filters(key, _b(q, "card"), _b(q, "dept"), _b(q, "from"), _b(q, "to"))
    rsql = reader_sql(door_roles(c))       # pary drzwi: odbicie na drzwiach wyjścia pokazane jako wyjście
    try:
        page = max(int(_b(q, "page", "1")), 1)
    except ValueError:
        page = 1
    with db() as con:
        total = con.execute(f"SELECT COUNT(*) FROM swipes s WHERE {where}", args).fetchone()[0]
        rows = [dict(r) for r in con.execute(
            f"SELECT s.record, s.time, s.card, s.name, s.door, {rsql} AS reader, s.granted, s.status, s.reason, "
            f"{PASSED_SQL} AS passed, COALESCE(p.name, '') AS person, d.name AS dept FROM swipes s "
            "LEFT JOIN people p ON p.card = s.card LEFT JOIN departments d ON d.id = p.dept_id "
            f"WHERE {where} ORDER BY s.time DESC, s.record DESC LIMIT ? OFFSET ?",
            args + [LOG_PAGE_SIZE, (page - 1) * LOG_PAGE_SIZE])]
    denied = [r for r in rows if r["card"] and not r["granted"] and not r["passed"]]
    # listę kart czytamy tylko wtedy, gdy na stronie jest odmowa, przy której ma to znaczenie
    cards = _cards_now(c) if any(r["reason"] in DENY_NOT_STORED or not r["reason"] for r in denied) else None
    for r in denied:
        r["on_ctrl"] = None if cards is None else r["card"] in cards
        r["reason_text"] = deny_text(r["reason"], r["on_ctrl"])
    return {"rows": rows, "total": total, "page": page,
            "pages": max((total + LOG_PAGE_SIZE - 1) // LOG_PAGE_SIZE, 1), "sync": _sync_public(key)}


# -- czas pracy --
def work_sessions(events, now):
    """Łączy odbicia jednej karty w pobyty. events = [(datetime, "in"|"out"[, korekta])] rosnąco.
    Zwraca (pobyty, wyjścia bez wejścia). Pobyt: start, end, state, manual (notatki korekt):
      ok      - wejście i wyjście,
      ongoing - wejście dziś, bez wyjścia (liczone do teraz),
      no_out  - brak odbicia przy wyjściu (nie liczony).
    Powtórne wejście w trakcie pobytu (podwójne przyłożenie, wejście bez wyjścia na przerwę)
    nie przerywa pobytu - liczy się od pierwszego wejścia."""
    sessions, stray = [], []
    start, manual = None, []
    for item in events:
        t, reader, note = item[0], item[1], (item[2] if len(item) > 2 else None)
        if start is not None and (t - start).total_seconds() > MAX_SESSION:
            sessions.append({"start": start, "end": None, "state": "no_out", "manual": manual})
            start, manual = None, []
        if reader == "in":
            if start is None:
                start, manual = t, ([note] if note is not None else [])
        elif start is None:
            stray.append(t)
        else:
            sessions.append({"start": start, "end": t, "state": "ok",
                             "manual": manual + ([note] if note is not None else [])})
            start, manual = None, []
    if start is not None:
        if start.date() == now.date() and 0 <= (now - start).total_seconds() <= MAX_SESSION:
            sessions.append({"start": start, "end": now, "state": "ongoing", "manual": manual})
        else:
            sessions.append({"start": start, "end": None, "state": "no_out", "manual": manual})
    return sessions, stray


def easter(year):
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    return datetime.date(year, month, (h + l - 7 * m + 114) % 31 + 1)


def pl_holidays(year):
    """Dni wolne od pracy w Polsce (ustawa o dniach wolnych; Wigilia od 2025)."""
    e = easter(year)
    days = {datetime.date(year, 1, 1): "Nowy Rok", datetime.date(year, 1, 6): "Trzech Króli",
            e: "Wielkanoc", e + datetime.timedelta(days=1): "Lany Poniedziałek",
            datetime.date(year, 5, 1): "Święto Pracy", datetime.date(year, 5, 3): "Święto Konstytucji 3 Maja",
            e + datetime.timedelta(days=49): "Zielone Świątki", e + datetime.timedelta(days=60): "Boże Ciało",
            datetime.date(year, 8, 15): "Wniebowzięcie NMP", datetime.date(year, 11, 1): "Wszystkich Świętych",
            datetime.date(year, 11, 11): "Święto Niepodległości", datetime.date(year, 12, 25): "Boże Narodzenie",
            datetime.date(year, 12, 26): "Drugi dzień Bożego Narodzenia"}
    if year >= 2025:
        days[datetime.date(year, 12, 24)] = "Wigilia"
    return dict(sorted(days.items()))


def pl_holidays_public(q):
    try:
        year = int(_b(q, "year", str(datetime.date.today().year)))
    except ValueError:
        raise ControllerError("Nieprawidłowy rok")
    return {"year": year, "holidays": [{"date": d.isoformat(), "name": n} for d, n in pl_holidays(year).items()]}


def _free_days(c, d_from, d_to, cfg):
    """Dni wolne w okresie: święta ustawowe (jeśli włączone) i wyjątki „brak wejścia” z godzin wejścia kontrolera."""
    free = {}
    if cfg.get("holidays_pl", True):
        for y in range(d_from.year, d_to.year + 1):
            free.update(pl_holidays(y))
    for h in _entry_cfg(c).get("holidays", []):
        if h["mode"] != "closed":
            continue
        d = max(datetime.date.fromisoformat(h["from"]), d_from)
        while d <= min(datetime.date.fromisoformat(h["to"]), d_to):
            free.setdefault(d, h["name"] or "dzień wolny")
            d += datetime.timedelta(days=1)
    return free


def worktime(q, c=None):
    c = c or require_active()
    key = ctrl_key(c)
    reason = tracking_reason(c)
    if reason:
        raise ControllerError(reason)
    tracked = tracked_doors(c)
    roles = door_roles(c)
    place = _b(q, "place", "all")
    if place in ("", "all") or roles:      # pary drzwi: wejście na jednych, wyjście na drugich - tylko razem
        doors = tracked
    elif place.isdigit() and int(place) in tracked:
        doors = [int(place)]
    else:
        raise ControllerError("Te drzwi nie mają włączonej analizy czasu pracy")
    today = datetime.date.today()
    d_from = _day(_b(q, "from"), today.replace(day=1))
    d_to = _day(_b(q, "to"), today)
    if d_to < d_from:
        raise ControllerError("Data „do” jest wcześniejsza niż „od”")
    if (d_to - d_from).days > 400:
        raise ControllerError("Raport obejmuje najwyżej 400 dni")
    card, dept = _b(q, "card"), _b(q, "dept")
    # dzień zapasu z obu stron - nocna zmiana zaczęta dzień wcześniej / skończona dzień później
    one = datetime.timedelta(days=1)
    where, args = _log_filters(key, card, dept, (d_from - one).isoformat(), (d_to + one).isoformat())
    rsql = reader_sql(roles)
    where += (f" AND (s.granted = 1 OR {PASSED_SQL}) AND s.card <> '' AND {rsql} IN ('in', 'out')"
              f" AND s.door IN ({','.join('?' * len(doors))})")
    cwhere, cargs = _log_filters(key, card, dept, (d_from - one).isoformat(), (d_to + one).isoformat())
    with db() as con:
        events = [(r["card"], r["time"], r["reader"], None, r["record"]) for r in con.execute(
            f"SELECT s.card, s.time, {rsql} AS reader, s.record FROM swipes s WHERE {where}", args + doors)]
        corr = [dict(r) for r in con.execute(
            f"SELECT s.id, s.card, s.time, s.reader, s.note, s.login, s.created FROM work_corrections s "
            f"WHERE {cwhere} AND s.deleted = ''", cargs)]
        people = _people_map(con)
        names = _log_names(con, key)
        alias = card_aliases(con)
    events += [(r["card"], r["time"], r["reader"], r, 0) for r in corr]
    # wymienione karty: odbicia starej karty liczą się osobie z nową kartą
    events = [(alias.get(e[0], e[0]),) + tuple(e[1:]) for e in events]
    events.sort(key=lambda e: (e[0], e[1], e[4]))
    wcfg = setting("work")
    free = _free_days(c, d_from, d_to, wcfg)
    tolerance = int(wcfg.get("late_tolerance") or 0)
    now = datetime.datetime.now()
    out = {}
    for card_no, evs in itertools.groupby(events, key=lambda r: r[0]):
        parsed = []
        for _, t, reader, note, _rec in evs:
            try:
                parsed.append((datetime.datetime.strptime(t, "%Y-%m-%d %H:%M:%S"), reader, note))
            except ValueError:
                continue
        sessions, stray = work_sessions(parsed, now)
        days = {}

        def day(dt):
            return days.setdefault(dt.date().isoformat(),
                                   {"date": dt.date().isoformat(), "seconds": 0, "sessions": [], "stray": []})
        for s_ in sessions:
            if not d_from <= s_["start"].date() <= d_to:
                continue
            sec = int((s_["end"] - s_["start"]).total_seconds()) if s_["end"] else 0
            d = day(s_["start"])
            d["seconds"] += sec
            d["sessions"].append({"in": s_["start"].strftime("%Y-%m-%d %H:%M:%S"),
                                  "out": s_["end"].strftime("%Y-%m-%d %H:%M:%S") if s_["end"] else "",
                                  "seconds": sec, "state": s_["state"],
                                  "manual": [{"id": m["id"], "time": m["time"], "reader": m["reader"], "note": m["note"],
                                              "login": m["login"]} for m in s_["manual"]]})
        for t in stray:
            if d_from <= t.date() <= d_to:
                day(t)["stray"].append(t.strftime("%Y-%m-%d %H:%M:%S"))
        if days:
            out[card_no] = {"card": card_no, "days": [days[k] for k in sorted(days)]}
    # przy filtrze pracownika / działu pokaż też osoby bez odbić w okresie
    if card_key(card) or dept:
        for p in people.values():
            if (card_key(card) and p["card"] != card_key(card)) or \
               (dept == "none" and p["dept_id"]) or (str(dept).isdigit() and p["dept_id"] != int(dept)):
                continue
            out.setdefault(p["card"], {"card": p["card"], "days": []})
    rows = []
    last_day = min(d_to, today)
    work_days = [d_from + datetime.timedelta(days=i) for i in range((d_to - d_from).days + 1)]
    work_days = [d for d in work_days if d.weekday() < 5 and d not in free]
    for card_no, r in out.items():
        p = people.get(card_no) or {}
        dcfg = wcfg.get("depts", {}).get(str(p.get("dept_id")), {}) if p.get("dept_id") else {}
        norm = int(dcfg.get("norm_min") or wcfg.get("norm_min") or 0) * 60
        shift_start = dcfg.get("start") or ""
        sess = [s_ for d in r["days"] for s_ in d["sessions"]]
        by_day = {d["date"]: d for d in r["days"]}
        overtime = late_count = late_min = 0
        for d in r["days"]:
            dd = datetime.date.fromisoformat(d["date"])
            d["free"] = free.get(dd) or ("weekend" if dd.weekday() >= 5 else "")
            d["overtime"] = d["seconds"] if d["free"] else max(0, d["seconds"] - norm) if norm else 0
            overtime += d["overtime"]
            d["late"] = 0
            if shift_start and not d["free"] and d["sessions"]:
                first = d["sessions"][0]["in"][11:16]
                h, m = map(int, shift_start.split(":"))
                fh, fm = map(int, first.split(":"))
                late = (fh * 60 + fm) - (h * 60 + m)
                if late > tolerance:
                    d["late"] = late
                    late_count += 1
                    late_min += late
        due = [d for d in work_days if d <= last_day]
        absent = [d.isoformat() for d in due if d < today and d.isoformat() not in by_day]
        seconds = sum(d["seconds"] for d in r["days"])
        norm_total = norm * len(due)
        r.update(name=p.get("name") or names.get(card_no, ""), dept=p.get("dept"), dept_id=p.get("dept_id"),
                 seconds=seconds, days_worked=sum(1 for d in r["days"] if d["seconds"]),
                 issues=sum(1 for s_ in sess if s_["state"] == "no_out") + sum(len(d["stray"]) for d in r["days"]),
                 inside=any(s_["state"] == "ongoing" for s_ in sess), corrections=sum(len(s_["manual"]) for s_ in sess),
                 norm_seconds=norm_total, balance=seconds - norm_total if norm else None, overtime=overtime,
                 late_count=late_count, late_minutes=late_min, absent=absent, shift_start=shift_start,
                 norm_day=norm)
        rows.append(r)
    rows.sort(key=lambda r: ((r["dept"] or "~").lower(), (r["name"] or "~").lower(), r["card"]))
    return {"from": d_from.isoformat(), "to": d_to.isoformat(), "doors": doors, "rows": rows,
            "seconds": sum(r["seconds"] for r in rows), "sync": _sync_public(key),
            "generated": now.strftime("%Y-%m-%d %H:%M:%S"), "work_days": len([d for d in work_days if d <= last_day]),
            "work_days_total": len(work_days), "free": {d.isoformat(): n for d, n in sorted(free.items())},
            "controller": saved_name(c) or c.host}


def _hm(sec):
    sign = "-" if sec < 0 else ""
    sec = abs(int(sec))
    return f"{sign}{sec // 3600}:{sec % 3600 // 60:02d}"


def worktime_csv(q):
    rep = worktime(q)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Dział", "Pracownik", "Nr karty", "Data", "Wejście", "Wyjście", "Czas (h:mm)", "Minuty", "Uwagi"])
    notes = {"ongoing": "w środku (liczone do chwili raportu)", "no_out": "brak odbicia przy wyjściu - nie liczone"}
    for r in rep["rows"]:
        base = [r["dept"] or "", r["name"], r["card"]]
        for d in r["days"]:
            for s_ in d["sessions"]:
                extra = [notes.get(s_["state"], "")] + [f"korekta ({m['login']}): {m['note']}" for m in s_["manual"]]
                if d.get("late"):
                    extra.append(f"spóźnienie {d['late']} min")
                w.writerow(base + [d["date"], s_["in"][11:], s_["out"][11:],
                                   _hm(s_["seconds"]), s_["seconds"] // 60, "; ".join(x for x in extra if x)])
            for t in d["stray"]:
                w.writerow(base + [d["date"], "", t[11:], "", "", "brak odbicia przy wejściu - nie liczone"])
        summary = [f"dni z pracą: {r['days_worked']}", f"nadgodziny: {_hm(r['overtime'])}"]
        if r["balance"] is not None:
            summary += [f"norma: {_hm(r['norm_seconds'])}", f"saldo: {_hm(r['balance'])}"]
        if r["late_count"]:
            summary.append(f"spóźnienia: {r['late_count']} ({r['late_minutes']} min)")
        if r["absent"]:
            summary.append(f"dni robocze bez odbić: {len(r['absent'])}")
        w.writerow(base + ["RAZEM", "", "", _hm(r["seconds"]), r["seconds"] // 60, "; ".join(summary)])
    return rep, "\ufeff" + buf.getvalue()


def correction_add(card, when, reader, note):
    c = require_active()
    k = card_key(card)
    if not k:
        raise ControllerError("Wybierz pracownika")
    try:
        t = datetime.datetime.strptime((when or "").strip().replace("T", " ")[:16], "%Y-%m-%d %H:%M")
    except ValueError:
        raise ControllerError("Podaj datę i godzinę odbicia")
    if t > datetime.datetime.now() + datetime.timedelta(minutes=5):
        raise ControllerError("Korekta nie może dotyczyć przyszłości")
    if reader not in ("in", "out"):
        raise ControllerError("Wybierz wejście albo wyjście")
    note = (note or "").strip()[:200]
    if not note:
        raise ControllerError("Podaj powód korekty - zostanie w raporcie")
    sess = getattr(_REQ, "session", None)
    with db() as con:
        cur = con.execute("INSERT INTO work_corrections(ctrl, card, time, reader, note, login, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (ctrl_key(c), k, t.strftime("%Y-%m-%d %H:%M:%S"), reader, note,
                           sess["login"] if sess else "system", _now_str()))
    return {"ok": True, "id": cur.lastrowid, "msg": "Dopisano " + ("wejście" if reader == "in" else "wyjście")
            + f" {t.strftime('%Y-%m-%d %H:%M')}"}


def correction_delete(cid):
    c = require_active()
    with db() as con:
        r = con.execute("SELECT * FROM work_corrections WHERE id = ? AND ctrl = ? AND deleted = ''",
                        (cid, ctrl_key(c))).fetchone()
        if r is None:
            raise ControllerError("Nie znaleziono korekty")
        con.execute("UPDATE work_corrections SET deleted = ? WHERE id = ?", (_now_str(), cid))
    return {"ok": True, "msg": f"Usunięto korektę karty {r['card']} z {r['time'][:16]}", "card": r["card"], "time": r["time"]}


def work_settings():
    cfg = setting("work")
    return {"settings": cfg, "departments": departments()}


def work_settings_save(raw):
    try:
        new = json.loads(raw or "{}")
    except ValueError:
        raise ControllerError("Nieprawidłowe ustawienia czasu pracy")
    cfg = _merge(SETTINGS_DEFAULTS["work"], new)
    try:
        cfg["norm_min"] = max(0, min(24 * 60, int(round(float(cfg["norm_min"])))))
        cfg["late_tolerance"] = max(0, min(240, int(cfg["late_tolerance"])))
        depts = {}
        for k, v in (cfg.get("depts") or {}).items():
            if not str(k).isdigit() or not isinstance(v, dict):
                continue
            item = {}
            if str(v.get("norm_min", "")).strip() != "":
                item["norm_min"] = max(0, min(24 * 60, int(round(float(v["norm_min"])))))
            if v.get("start"):
                item["start"] = _hhmm(v["start"])
            if item:
                depts[str(k)] = item
        cfg["depts"] = depts
    except (TypeError, ValueError):
        raise ControllerError("Nieprawidłowa liczba w ustawieniach czasu pracy")
    cfg["holidays_pl"] = bool(cfg.get("holidays_pl"))
    setting_save("work", cfg)
    return dict(work_settings(), ok=True)


# --- zdarzenia na żywo, obecni, powiadomienia -----------------------------------
# Dla każdego połączonego kontrolera wątek co sekundę czyta stan (UDP 0x20) i nowe rekordy (0xB0): zapisuje je
# w live_events, pokazuje na pulpicie i sprawdza reguły powiadomień. Log przejść ze strony WWW (swipes)
# pozostaje źródłem historii - zdarzenia na żywo uzupełniają go między pobraniami.
LIVE_POLL = 1.0
LIVE_KEEP = 200
_LIVE = {}                  # ctrl_key -> {"events": deque, "seq": int, "state": ..., "error": ...}
_LIVE_SEQ = itertools.count(1)
_LIVE_LOCK = threading.RLock()


def _live_state(key):
    with _LIVE_LOCK:
        return _LIVE.setdefault(key, {"events": collections.deque(maxlen=LIVE_KEEP), "state": "off", "error": ""})


def event_in(ev, roles=None):
    """Czy odbicie jest wejściem: rola drzwi (pary drzwi, ACB-004), a bez niej czytnik z rekordu."""
    role = (roles or {}).get(ev["door"])
    return role == "in" if role else ev["dir"] == WG_DIR_IN


def event_text(ev, roles=None):
    reason = WG_REASONS.get(ev["reason"], f"kod {ev['reason']}")
    if ev["type"] == WG_EVENT_SWIPE:
        where = "wejście" if event_in(ev, roles) else "wyjście"
        return where if ev["granted"] else f"odmowa ({where}): {reason}"
    if ev["type"] == 3:
        return f"alarm: {reason}"
    return reason


def event_kind(ev, roles=None):
    if ev["type"] == 3 or ev["reason"] in WG_ALARM_REASONS:
        return "alarm"
    if ev["type"] == WG_EVENT_SWIPE:
        return ("in" if event_in(ev, roles) else "out") if ev["granted"] else "denied"
    return "device"


def _live_text(c, ev, card, roles=None):
    """Jak event_text, ale odmowę karty, której nie ma w kontrolerze, nazywa wprost (tylko z listy kart już
    odczytanej - podgląd na żywo nie odpytuje kontrolera o każdą odmowę)."""
    if ev["type"] == WG_EVENT_SWIPE and not ev["granted"] and ev["reason"] in DENY_NOT_STORED:
        hit = _CARDS_NOW.get(ctrl_key(c))
        cards = hit[1] if hit else _CARDS.get(ctrl_key(c))
        if cards is not None and card not in cards:
            return f"odmowa ({'wejście' if event_in(ev, roles) else 'wyjście'}): {NOT_STORED_TEXT}"
    return event_text(ev, roles)


def _live_public(c, ev, names, blocks, roles=None):
    card = card_key(ev["card"]) if ev["type"] == WG_EVENT_SWIPE else ""
    p = names.get(card) or {}
    doors = {d["n"]: d["name"] for d in c.info.get("doors_list", [])}
    return {"seq": next(_LIVE_SEQ), "ctrl": ctrl_key(c), "record": ev["record"],
            "time": ev["time"].strftime("%Y-%m-%d %H:%M:%S") if ev["time"] else "",
            "card": card, "name": p.get("name", ""), "dept": p.get("dept") or "", "door": ev["door"],
            "door_name": doors.get(ev["door"], ""), "kind": event_kind(ev, roles),
            "text": _live_text(c, ev, card, roles), "blocked": card in blocks,
            "alert": event_kind(ev, roles) in ("denied", "alarm")}


def _live_loop(c):
    key = ctrl_key(c)
    st = _live_state(key)
    last, errors = None, 0
    while is_connected(c):
        try:
            wg = c.udp()
            ev = wg.last_event()
            if last is None or ev["record"] < last:
                last = ev["record"]
            elif ev["record"] > last:
                evs = [wg.event(i) for i in range(max(last + 1, ev["record"] - 49), ev["record"])] + [ev]
                last = ev["record"]
                with db() as con:
                    names = _people_map(con)
                    blocks = {r[0] for r in con.execute("SELECT card FROM card_blocks WHERE ctrl = ?", (key,))}
                roles = door_roles(c)
                with db() as con:
                    con.executemany(
                        "INSERT OR IGNORE INTO live_events(ctrl, record, time, type, granted, door, dir, card, reason) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [(key, e["record"], e["time"].strftime("%Y-%m-%d %H:%M:%S"), e["type"], int(e["granted"]),
                          e["door"], e["dir"], card_key(e["card"]) if e["type"] == WG_EVENT_SWIPE else "", e["reason"])
                         for e in evs if e["time"]])
                for e in evs:
                    if e["time"] is None:
                        continue
                    pub = _live_public(c, e, names, blocks, roles)
                    with _LIVE_LOCK:
                        st["events"].append(pub)
                    notify_event(c, e, pub)
                    _door_event(c, e)
            if not _doors_state(key)["init"]:
                _door_init(c, wg, last)
            _door_check(c)
            st.update(state="on", error="")
            errors = 0
        except Exception as e:
            errors += 1
            st.update(state="error", error=str(e))
            time.sleep(min(30, 2 * errors))
        time.sleep(LIVE_POLL)
    st.update(state="off", error="")


def live(q):
    c = require_active()
    try:
        after = int(_b(q, "after", "0"))
    except ValueError:
        after = 0
    st = _live_state(ctrl_key(c))
    others = [(x, saved_name(x) or x.host, _live_state(ctrl_key(x))) for x in connected() if x is not c]
    with _LIVE_LOCK:
        evs = [e for e in st["events"] if e["seq"] > after]
        # alerty z innych połączonych kontrolerów - żeby oglądający jeden kontroler nie przegapił alarmu drugiego
        other = [dict(e, ctrl_name=name) for _, name, ost in others for e in ost["events"] if e["seq"] > after and e["alert"]]
        last = max([e["seq"] for e in st["events"]] + [e["seq"] for _, _, ost in others for e in ost["events"]] + [after])
    return {"events": evs[-50:], "other_alerts": other[-20:], "seq": last, "state": st["state"],
            "error": st["error"], "doors_open": doors_open_public()}


def presence_supported(c):
    return not roles_mode(c) or not tracking_reason(c)


DIR_SQL = "CASE dir WHEN 1 THEN 'in' ELSE 'out' END"     # kierunek z live_events (czytnik WG)


def presence(c=None):
    """Kto jest teraz w środku: ostatnie przyjęte odbicie karty z ostatnich 16 h na drzwiach liczących czas
    pracy (albo na wszystkich, gdy żadne nie są zaznaczone) jest wejściem. Źródła: kopia logu, zdarzenia
    na żywo i korekty czasu pracy."""
    c = c or require_active()
    if not presence_supported(c):
        raise ControllerError(tracking_reason(c) + " Bez tego panel nie ustali, kto jest w środku.")
    key = ctrl_key(c)
    roles = door_roles(c)
    doors = tracked_doors(c) or list(range(1, c.doors + 1))
    since = (datetime.datetime.now() - datetime.timedelta(seconds=MAX_SESSION)).strftime("%Y-%m-%d %H:%M:%S")
    marks = ",".join("?" * len(doors))
    with db() as con:
        rows = con.execute(
            f"SELECT card, time, {reader_sql(roles)} AS reader FROM swipes s WHERE ctrl = ? AND time >= ? "
            f"AND card <> '' AND {reader_sql(roles)} IN ('in', 'out') AND door IN ({marks}) "
            f"AND (granted = 1 OR {PASSED_SQL}) "
            f"UNION ALL SELECT card, time, {reader_sql(roles, 'door', DIR_SQL)} FROM live_events "
            f"WHERE ctrl = ? AND time >= ? AND type = 1 AND granted = 1 AND card <> '' AND door IN ({marks}) "
            "UNION ALL SELECT card, time, reader FROM work_corrections WHERE ctrl = ? AND time >= ? AND deleted = ''",
            [key, since, *doors, key, since, *doors, key, since]).fetchall()
        people = _people_map(con)
        names = _log_names(con, key)
        alias = card_aliases(con)
    last = {}
    for r in sorted(rows, key=lambda r: r["time"]):
        card = alias.get(r["card"], r["card"])      # stara karta po wymianie = ta sama osoba
        prev = last.get(card)
        if r["reader"] == "in":
            last[card] = {"state": "in", "since": prev["since"] if prev and prev["state"] == "in" else r["time"],
                               "last": r["time"]}
        else:
            last[card] = {"state": "out", "since": r["time"], "last": r["time"]}
    inside = []
    for card, v in last.items():
        if v["state"] != "in":
            continue
        p = people.get(card) or {}
        inside.append({"card": card, "name": p.get("name") or names.get(card, ""), "dept": p.get("dept") or "",
                       "since": v["since"], "last": v["last"]})
    inside.sort(key=lambda x: ((x["dept"] or "~").lower(), (x["name"] or "~").lower(), x["card"]))
    return {"inside": inside, "count": len(inside), "doors": doors, "generated": _now_str(),
            "sync": _sync_public(key), "controller": saved_name(c) or c.host}


def presence_state(q):
    c = require_active()
    st = _sync_public(ctrl_key(c))
    # log ze strony WWW dociąga się w tle, gdy dawno nie był pobierany (zdarzenia na żywo są od startu panelu)
    if not st["running"] and (not st.get("finished") or time.time() - st["finished"] > 300):
        with contextlib.suppress(ControllerError):
            swipe_sync_start(c)
    return presence(c)


# -- drzwi otwarte zbyt długo --
# Firmware ACB nie wysyła alarmu „drzwi otwarte zbyt długo” (kod 37) - test 2026-09-17 na ACB-002: drzwi
# otwarte ponad 3,5 min dały tylko zdarzenia 23/24 w typie 2. Czas otwarcia liczy więc panel: dla drzwi
# zaznaczonych w zakładce „Drzwi” pilnuje, czy między „drzwi otwarte” (23) a „drzwi zamknięte” (24) nie
# minęło więcej minut, niż ustawiono. Stan drzwi bierze się z kolejności REKORDÓW, nie ze stempli czasu -
# drgania styku dają kilka zdarzeń 23/24 w tej samej sekundzie (sprzęt 2026-09-17, rekordy 215-219).
DOOR_OPEN_MIN_DEFAULT = 5
DOOR_OPEN_MIN_MAX = 1440
DOOR_OPEN_SCAN_BACK = 60        # ile rekordów kontrolera przejrzeć wstecz w poszukiwaniu stanu drzwi
DOOR_OPEN_HISTORY_DAYS = 30
_DOORS = {}                     # ctrl_key -> {"init": bool, "watch": {drzwi: minuty}, "doors": {drzwi: stan}}
_DOORS_LOCK = threading.RLock()


def _doors_state(key):
    with _DOORS_LOCK:
        return _DOORS.setdefault(key, {"init": False, "watch": {}, "doors": {}})


def door_watch_map(key):
    """Drzwi pilnowane na tym kontrolerze: {nr drzwi: minuty do ostrzeżenia}."""
    with db() as con:
        return {r["door"]: max(1, int(r["minutes"] or DOOR_OPEN_MIN_DEFAULT))
                for r in con.execute("SELECT door, minutes FROM door_open_watch WHERE ctrl = ?", (key,))}


def _stamp(text):
    return datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def _door_name(c, door):
    return {d["n"]: d["name"] for d in c.info.get("doors_list", [])}.get(door, "")


def _door_label(c, door):
    name = _door_name(c, door)
    return f"drzwi #{door}" + (f" {name}" if name else "")


def dur_pl(sec):
    """Czas trwania po ludzku: „42 s”, „7 min”, „2 h 5 min”."""
    sec = max(0, int(sec))
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        return f"{sec // 60} min"
    return f"{sec // 3600} h {sec % 3600 // 60} min"


def _door_db_state(key, doors):
    """Ostatnie zdarzenie otwarcia/zamknięcia tych drzwi z zapisu panelu: zdarzenia na żywo i kopia logu
    przejść mają ten sam numer rekordu, więc wystarczy najwyższy."""
    out = {}
    with db() as con:
        for door in doors:
            r = con.execute(
                "SELECT record, time, CASE WHEN reason = ? THEN 1 ELSE 0 END AS open FROM live_events "
                "WHERE ctrl = ? AND door = ? AND type = ? AND reason IN (?, ?) "
                "UNION SELECT record, time, CASE WHEN status LIKE 'Door Open%' THEN 1 ELSE 0 END FROM swipes "
                "WHERE ctrl = ? AND door = ? AND (status LIKE 'Door Open%' OR status LIKE 'Door Closed%') "
                "ORDER BY record DESC LIMIT 1",
                (WG_REASON_DOOR_OPEN, key, door, WG_EVENT_DOOR, WG_REASON_DOOR_OPEN, WG_REASON_DOOR_CLOSED,
                 key, door)).fetchone()
            if not r:
                continue
            with contextlib.suppress(ValueError):
                out[door] = {"open": bool(r["open"]), "since": _stamp(r["time"]), "record": int(r["record"]),
                             "warned": False}
    return out


def _door_init(c, wg, last_record):
    """Stan pilnowanych drzwi po połączeniu i po zmianie ustawień: z ostatnich rekordów kontrolera (0xB0),
    a dla drzwi, których tam nie ma - z zapisu panelu. Bez tego drzwi otwarte przed startem panelu
    byłyby niewidoczne aż do następnego otwarcia."""
    key = ctrl_key(c)
    watch = door_watch_map(key)
    found, last_record = {}, int(last_record or 0)
    for i in range(last_record, max(0, last_record - DOOR_OPEN_SCAN_BACK), -1):
        if len(found) >= len(watch):
            break
        e = wg.event(i)
        if (e["type"] == WG_EVENT_DOOR and e["time"] and e["door"] in watch and e["door"] not in found
                and e["reason"] in (WG_REASON_DOOR_OPEN, WG_REASON_DOOR_CLOSED)):
            found[e["door"]] = {"open": e["reason"] == WG_REASON_DOOR_OPEN, "since": e["time"],
                                "record": e["record"], "warned": False}
    if len(found) < len(watch):
        found.update(_door_db_state(key, set(watch) - set(found)))
    st = _doors_state(key)
    with _DOORS_LOCK:
        for door, v in found.items():
            prev = st["doors"].get(door)
            if prev and prev["record"] == v["record"] and prev["open"] == v["open"]:
                v["warned"] = prev["warned"]        # nie powtarzaj ostrzeżenia po zmianie ustawień
        st.update(doors=found, watch=watch, init=True)
    return True


def _door_feed(c, door, kind, text, when=None):
    """Wpis panelu (nie kontrolera) w podglądzie na żywo - jak zdarzenie, ale bez numeru rekordu."""
    pub = {"seq": next(_LIVE_SEQ), "ctrl": ctrl_key(c), "record": 0,
           "time": (when or datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
           "card": "", "name": "", "dept": "", "door": door, "door_name": _door_name(c, door),
           "kind": kind, "text": text, "blocked": False, "alert": kind == "warn"}
    with _LIVE_LOCK:
        _live_state(ctrl_key(c))["events"].append(pub)
    return pub


def _door_open_warn(c, door, since, minutes):
    ctrl = saved_name(c) or c.host
    _door_feed(c, door, "warn", f"drzwi otwarte dłużej niż {minutes} min (od {since:%H:%M:%S})")
    notify("door_open", f"{ctrl_key(c)}:{door}", f"🚪 Drzwi otwarte dłużej niż {minutes} min",
           f"{ctrl}, {_door_label(c, door)}\nOtwarte od {since:%Y-%m-%d %H:%M:%S}.")


def _door_closed_info(c, door, since, when):
    ctrl = saved_name(c) or c.host
    took = dur_pl((when - since).total_seconds())
    _door_feed(c, door, "info", f"drzwi zamknięte po {took}", when)
    notify("door_open", f"{ctrl_key(c)}:{door}:closed", f"✅ Drzwi znów zamknięte (po {took})",
           f"{ctrl}, {_door_label(c, door)}\nOtwarte {since:%Y-%m-%d %H:%M:%S} - {when:%Y-%m-%d %H:%M:%S}.")


def _door_event(c, ev):
    """Zdarzenie otwarcia/zamknięcia drzwi - aktualizuje stan; „drzwi znów zamknięte” tylko po ostrzeżeniu."""
    if (ev["type"] != WG_EVENT_DOOR or not ev["time"]
            or ev["reason"] not in (WG_REASON_DOOR_OPEN, WG_REASON_DOOR_CLOSED)):
        return
    st = _doors_state(ctrl_key(c))
    opened, closed_after = ev["reason"] == WG_REASON_DOOR_OPEN, None
    with _DOORS_LOCK:
        if ev["door"] not in st["watch"]:
            return
        cur = st["doors"].get(ev["door"])
        if cur and cur["record"] > ev["record"]:
            return                          # starszy rekord (dogrywka zaległości) nie cofa stanu
        if cur and cur["open"] == opened:
            cur["record"] = ev["record"]    # ten sam stan (np. drgania styku) - początek otwarcia bez zmian
            return
        if cur and cur["open"] and not opened and cur["warned"]:
            closed_after = cur["since"]
        st["doors"][ev["door"]] = {"open": opened, "since": ev["time"], "record": ev["record"], "warned": False}
    if closed_after is not None:
        _door_closed_info(c, ev["door"], closed_after, ev["time"])


def _door_check(c):
    """Co sekundę dla połączonego kontrolera: które pilnowane drzwi są otwarte ponad zadany czas."""
    now, warn = datetime.datetime.now(), []
    st = _doors_state(ctrl_key(c))
    with _DOORS_LOCK:
        for door, minutes in st["watch"].items():
            d = st["doors"].get(door)
            if not d or not d["open"] or d["warned"]:
                continue
            if (now - d["since"]).total_seconds() >= minutes * 60:
                d["warned"] = True
                warn.append((door, d["since"], minutes))
    for door, since, minutes in warn:
        _door_open_warn(c, door, since, minutes)


def doors_open_public():
    """Pilnowane drzwi, które są teraz otwarte - u wszystkich połączonych kontrolerów (pulpit)."""
    now, out = datetime.datetime.now(), []
    for c in connected():
        st = _doors_state(ctrl_key(c))
        with _DOORS_LOCK:
            items = [(n, m, dict(st["doors"][n])) for n, m in st["watch"].items()
                     if st["doors"].get(n, {}).get("open")]
        for door, minutes, d in items:
            secs = max(0, int((now - d["since"]).total_seconds()))
            out.append({"ctrl": ctrl_key(c), "ctrl_name": saved_name(c) or c.host, "door": door,
                        "door_name": _door_name(c, door), "since": d["since"].strftime("%Y-%m-%d %H:%M:%S"),
                        "seconds": secs, "minutes": minutes, "over": secs >= minutes * 60})
    out.sort(key=lambda x: -x["seconds"])
    return out


def door_open_history(c, watch, limit=20):
    """Zakończone otwarcia dłuższe niż próg (drzwi bez pilnowania liczą się od 5 min) z ostatnich
    30 dni - z zapisu zdarzeń na żywo i kopii logu przejść, sklejone po numerze rekordu."""
    key = ctrl_key(c)
    since = (datetime.datetime.now() - datetime.timedelta(days=DOOR_OPEN_HISTORY_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as con:
        rows = con.execute(
            "SELECT door, record, time, CASE WHEN reason = ? THEN 1 ELSE 0 END AS open FROM live_events "
            "WHERE ctrl = ? AND time >= ? AND type = ? AND reason IN (?, ?) "
            "UNION SELECT door, record, time, CASE WHEN status LIKE 'Door Open%' THEN 1 ELSE 0 END FROM swipes "
            "WHERE ctrl = ? AND time >= ? AND (status LIKE 'Door Open%' OR status LIKE 'Door Closed%')",
            (WG_REASON_DOOR_OPEN, key, since, WG_EVENT_DOOR, WG_REASON_DOOR_OPEN, WG_REASON_DOOR_CLOSED,
             key, since)).fetchall()
    opened, out = {}, []
    for r in sorted(rows, key=lambda r: (int(r["record"]), r["time"])):
        door = r["door"] or 0
        if r["open"]:
            opened.setdefault(door, r["time"])       # kolejne „otwarte” nie przestawia początku
            continue
        start = opened.pop(door, None)
        if start is None:
            continue
        try:
            secs = (_stamp(r["time"]) - _stamp(start)).total_seconds()
        except ValueError:
            continue
        if secs >= watch.get(door, DOOR_OPEN_MIN_DEFAULT) * 60:
            out.append({"door": door, "door_name": _door_name(c, door), "from": start, "to": r["time"],
                        "seconds": int(secs), "text": dur_pl(secs)})
    out.sort(key=lambda x: x["from"], reverse=True)
    return out[:limit]


def door_watch_config():
    c = require_active()
    key = ctrl_key(c)
    watch = door_watch_map(key)
    names = {d["n"]: d["name"] for d in c.info.get("doors_list", [])}
    now = datetime.datetime.now()
    st = _doors_state(key)
    with _DOORS_LOCK:
        cur = {n: dict(v) for n, v in st["doors"].items()}
    doors = []
    for n in range(1, c.doors + 1):
        d = cur.get(n)
        doors.append({"n": n, "name": names.get(n, ""), "enabled": n in watch,
                      "minutes": watch.get(n, DOOR_OPEN_MIN_DEFAULT),
                      "state": ("open" if d["open"] else "closed") if d else "",
                      "since": d["since"].strftime("%Y-%m-%d %H:%M:%S") if d else "",
                      "seconds": max(0, int((now - d["since"]).total_seconds())) if d else 0})
    return {"doors": doors, "default_minutes": DOOR_OPEN_MIN_DEFAULT, "history_days": DOOR_OPEN_HISTORY_DAYS,
            "events_on": bool(re.search("enab", str(c.info.get("events", "")), re.I)),
            "notify_on": bool(setting("notify")["rules"].get("door_open", {}).get("on")),
            "history": door_open_history(c, watch)}


def door_watch_set(door, enabled, minutes):
    c = require_active()
    door = c._door(door)
    try:
        minutes = int(minutes or DOOR_OPEN_MIN_DEFAULT)
    except (TypeError, ValueError):
        raise ControllerError("Podaj czas otwarcia w minutach")
    if not 1 <= minutes <= DOOR_OPEN_MIN_MAX:
        raise ControllerError(f"Czas do ostrzeżenia: od 1 do {DOOR_OPEN_MIN_MAX} minut")
    key = ctrl_key(c)
    with db() as con:
        if enabled:
            con.execute("INSERT INTO door_open_watch(ctrl, door, minutes) VALUES (?, ?, ?) "
                        "ON CONFLICT(ctrl, door) DO UPDATE SET minutes = excluded.minutes", (key, door, minutes))
        else:
            con.execute("DELETE FROM door_open_watch WHERE ctrl = ? AND door = ?", (key, door))
    with _DOORS_LOCK:
        _doors_state(key)["init"] = False       # wątek zdarzeń odczyta stan drzwi na nowo (do 1 s)
    st = door_watch_config()
    return dict(st, ok=True, msg=(f"{_door_label(c, door)}: ostrzeżenie po {minutes} min" if enabled
                                  else f"{_door_label(c, door)}: bez pilnowania czasu otwarcia"))


# -- powiadomienia --
NOTIFY_RULES = {
    "denied_repeat": "Powtarzające się odmowy tej samej karty",
    "unknown_card": "Nieznana karta przy czytniku",
    "blocked_card": "Próba użycia zablokowanej karty",
    "after_hours": "Wejście poza godzinami pracy",
    "alarm": "Alarm drzwi (otwarte zbyt długo, wymuszone otwarcie, pożar)",
    "door_open": "Drzwi otwarte dłużej niż ustawiony czas (liczy panel)",
    "offline": "Kontroler bez połączenia",
    "test": "Wiadomość testowa",
}
_NOTIFY_Q = collections.deque()
_NOTIFY_WAKE = threading.Event()
_NOTIFY_LAST = {}           # (reguła, klucz) -> czas ostatniego wysłania
_DENIED = {}                # (kontroler, karta) -> czasy odmów


def notify(rule, key, title, text):
    cfg = setting("notify")
    if rule != "test":
        if not cfg["rules"].get(rule, {}).get("on"):
            return False
        now = time.time()
        if now - _NOTIFY_LAST.get((rule, key), 0) < float(cfg.get("cooldown") or 0) * 60:
            return False
        _NOTIFY_LAST[(rule, key)] = now
    _NOTIFY_Q.append((rule, title, text))
    _NOTIFY_WAKE.set()
    return True


def notify_event(c, ev, pub):
    rules = setting("notify")["rules"]
    who = pub["name"] or (f"karta {pub['card']}" if pub["card"] else "")
    ctrl = saved_name(c) or c.host
    door = f"drzwi #{ev['door']}" + (f" {pub['door_name']}" if pub["door_name"] else "")
    head = f"{ctrl}, {door}, {pub['time']}"
    if pub["kind"] == "alarm":
        notify("alarm", f"{ctrl_key(c)}:{ev['door']}:{ev['reason']}",
               f"🚨 Alarm: {WG_REASONS.get(ev['reason'], 'kod ' + str(ev['reason']))}", head)
    if pub["kind"] == "denied":
        if ev["reason"] == WG_REASON_UNKNOWN_CARD:
            notify("unknown_card", f"{ctrl_key(c)}:{pub['card']}", "❓ Nieznana karta przy czytniku",
                   f"{head}\nKarta {pub['card'] or '(bez numeru)'} nie jest zapisana w kontrolerze.")
        if pub["blocked"]:
            notify("blocked_card", f"{ctrl_key(c)}:{pub['card']}", "⛔ Próba użycia zablokowanej karty",
                   f"{head}\n{who}" + (f" ({pub['dept']})" if pub["dept"] else ""))
        r = rules["denied_repeat"]
        if pub["card"] and r.get("on"):
            times = _DENIED.setdefault((ctrl_key(c), pub["card"]), collections.deque(maxlen=50))
            now = time.time()
            times.append(now)
            recent = [t for t in times if now - t <= float(r.get("minutes") or 5) * 60]
            if len(recent) >= int(r.get("count") or 3):
                notify("denied_repeat", f"{ctrl_key(c)}:{pub['card']}", f"⚠️ {len(recent)} odmowy dla: {who}",
                       f"{head}\nOstatnia odmowa: {pub['text']}")
    if pub["kind"] == "in":
        r = rules["after_hours"]
        if r.get("on"):
            try:
                window = {"mode": "hours", "start": _hhmm(r.get("start")), "end": _hhmm(r.get("end")),
                          "days": r.get("days") if re.fullmatch(r"[01]{7}", str(r.get("days"))) else "1111100"}
            except ControllerError:
                return
            if not group_allows(window, ev["time"]):
                notify("after_hours", f"{ctrl_key(c)}:{pub['card']}", f"🌙 Wejście poza godzinami: {who}",
                       head + (f"\nDział: {pub['dept']}" if pub["dept"] else ""))


def _send_email(cfg, title, text):
    e = cfg["email"]
    to = [x.strip() for x in re.split(r"[,;\s]+", e.get("to") or "") if x.strip()]
    if not (e.get("host") and to):
        raise ControllerError("uzupełnij serwer SMTP i adresata")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = f"[Spreest - Panel ACB] {title}", e.get("from") or e.get("user") or to[0], ", ".join(to)
    msg.set_content(text + "\n\n-- \nSpreest - Panel ACB (kontrola dostępu)")
    port = int(e.get("port") or (465 if e.get("security") == "ssl" else 587))
    if e.get("security") == "ssl":
        srv = smtplib.SMTP_SSL(e["host"], port, timeout=20, context=ssl.create_default_context())
    else:
        srv = smtplib.SMTP(e["host"], port, timeout=20)
    with srv:
        if e.get("security") == "starttls":
            srv.starttls(context=ssl.create_default_context())
        if e.get("user"):
            srv.login(e["user"], e.get("password") or "")
        srv.send_message(msg)


def _post_json(url, data):
    req = urllib.request.Request(url, data=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "User-Agent": f"acb-panel/{APP_VERSION}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read(2000)


def _send_telegram(cfg, title, text):
    t = cfg["telegram"]
    if not (t.get("token") and t.get("chat_id")):
        raise ControllerError("uzupełnij token bota i identyfikator czatu")
    _post_json(f"https://api.telegram.org/bot{t['token']}/sendMessage", {"chat_id": t["chat_id"], "text": f"{title}\n{text}"})


def _send_webhook(cfg, rule, title, text):
    url = cfg["webhook"].get("url") or ""
    if not re.match(r"https?://", url):
        raise ControllerError("adres musi zaczynać się od http:// albo https://")
    _post_json(url, {"text": f"{title}\n{text}", "title": title, "message": text, "rule": rule, "time": _now_str()})


def notify_send(rule, title, text):
    cfg = setting("notify")
    results = []
    for name, label, fn in (("email", "e-mail", lambda: _send_email(cfg, title, text)),
                            ("telegram", "Telegram", lambda: _send_telegram(cfg, title, text)),
                            ("webhook", "webhook", lambda: _send_webhook(cfg, rule, title, text))):
        if not cfg[name].get("enabled"):
            continue
        try:
            fn()
            results.append(f"{label}: wysłano")
        except Exception as e:
            results.append(f"{label}: błąd - {e}")
    result = "; ".join(results) or "brak włączonych kanałów"
    with db() as con:
        con.execute("INSERT INTO notify_log(time, rule, title, text, result) VALUES (?, ?, ?, ?, ?)",
                    (_now_str(), rule, title, text, result))
    return result


def _notify_loop():
    while True:
        _NOTIFY_WAKE.wait(30)
        _NOTIFY_WAKE.clear()
        while _NOTIFY_Q:
            rule, title, text = _NOTIFY_Q.popleft()
            try:
                notify_send(rule, title, text)
            except Exception as e:
                _devlog(f"NOTIFY błąd: {e}")


SECRET_FIELDS = (("email", "password"), ("telegram", "token"))


def notify_settings():
    cfg = setting("notify")
    for ch, field in SECRET_FIELDS:
        cfg[ch]["has_" + field] = bool(cfg[ch].get(field))
        cfg[ch][field] = ""
    with db() as con:
        log = [dict(r) for r in con.execute("SELECT time, rule, title, text, result FROM notify_log ORDER BY id DESC LIMIT 30")]
    return {"settings": cfg, "rules": NOTIFY_RULES, "log": log}


def notify_save(raw):
    try:
        new = json.loads(raw or "{}")
    except ValueError:
        raise ControllerError("Nieprawidłowe ustawienia powiadomień")
    old = setting("notify")
    cfg = _merge(SETTINGS_DEFAULTS["notify"], new)
    for ch, field in SECRET_FIELDS:
        if not cfg[ch].get(field) and not new.get(ch, {}).get("clear_" + field):
            cfg[ch][field] = old[ch].get(field, "")
        cfg[ch].pop("clear_" + field, None)
        cfg[ch].pop("has_" + field, None)
    try:
        cfg["email"]["port"] = int(cfg["email"].get("port") or 587)
        cfg["cooldown"] = max(0, int(cfg.get("cooldown") or 0))
        r = cfg["rules"]
        r["denied_repeat"]["count"] = max(2, int(r["denied_repeat"].get("count") or 3))
        r["denied_repeat"]["minutes"] = max(1, int(r["denied_repeat"].get("minutes") or 5))
        r["offline"]["minutes"] = max(1, int(r["offline"].get("minutes") or 5))
        _hhmm(r["after_hours"]["start"]), _hhmm(r["after_hours"]["end"])
    except (TypeError, ValueError):
        raise ControllerError("Nieprawidłowa liczba w ustawieniach powiadomień")
    if cfg["email"].get("security") not in ("starttls", "ssl", "none"):
        cfg["email"]["security"] = "starttls"
    if not re.fullmatch(r"[01]{7}", str(cfg["rules"]["after_hours"].get("days"))):
        raise ControllerError("Zaznacz dni tygodnia godzin pracy")
    setting_save("notify", cfg)
    return dict(notify_settings(), ok=True)


def notify_test():
    sess = getattr(_REQ, "session", None)
    result = notify_send("test", "Wiadomość testowa", f"Test powiadomień panelu ACB ({_now_str()}), wysłał: "
                         + (sess["login"] if sess else "system"))
    return {"ok": True, "msg": result}


def _offline_check(items):
    """Po każdym sprawdzeniu stanu online: powiadomienie o kontrolerze offline dłużej niż N minut i o powrocie."""
    r = setting("notify")["rules"]["offline"]
    if not r.get("on"):
        return
    now = time.time()
    with _ONLINE_LOCK:
        for e in items:
            o = _ONLINE.get(e["id"])
            if not o:
                continue
            if o["state"] == "offline" and not o.get("notified") and now - o["changed"] >= float(r.get("minutes") or 5) * 60:
                o["notified"] = True
                notify("offline", e["id"], f"🔴 Kontroler offline: {e.get('name') or e.get('host')}",
                       f"{e.get('host')} nie odpowiada od {_when(o['changed'])}"
                       + (f" (ostatnio online {_when(o['seen'])})" if o.get("seen") else ""))
            elif o["state"] == "online" and o.get("was_notified_offline"):
                o.pop("was_notified_offline")
                notify("offline", e["id"] + ":up", f"🟢 Kontroler znów online: {e.get('name') or e.get('host')}",
                       f"{e.get('host')} odpowiada od {_when(o['changed'])}")
            if o["state"] == "offline" and o.get("notified"):
                o["was_notified_offline"] = True


# --- strony do druku (lista obecnych, karta miesięczna czasu pracy) ----------------
PRINT_CSS = """
*{box-sizing:border-box}body{font:13px/1.4 system-ui,"Segoe UI",Roboto,sans-serif;color:#111;background:#fff;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:18px 0 6px}.muted{color:#555}.small{font-size:11px}
table{border-collapse:collapse;width:100%;margin-top:8px}th,td{border:1px solid #999;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#eee}tr.free td{background:#f3f3f3;color:#555}td.num{text-align:right;white-space:nowrap}
.bar{position:sticky;top:0;background:#fff;padding:0 0 12px;margin-bottom:12px;border-bottom:1px solid #ccc;display:flex;gap:10px;align-items:center}
.bar button{font:inherit;padding:6px 14px;cursor:pointer}.page{page-break-after:always;margin-bottom:32px}.page:last-child{page-break-after:auto}
.sign{display:flex;gap:40px;margin-top:40px}.sign div{flex:1;border-top:1px solid #333;padding-top:4px;text-align:center;font-size:11px}
.sum{margin-top:8px;display:flex;flex-wrap:wrap;gap:6px 18px}.check{width:26px}
@media print{.bar{display:none}body{padding:0}@page{margin:14mm}}
"""
WEEKDAY_NAMES = ("pon", "wt", "śr", "czw", "pt", "sob", "nd")


def _print_page(title, body):
    esc = html.escape
    return (f"<!doctype html><html lang='pl'><head><meta charset='utf-8'><title>{esc(title)} · Spreest - Panel ACB</title><link rel='icon' href='/favicon.png'>"
            f"<style>{PRINT_CSS}</style></head><body><div class='bar'><button onclick='print()'>🖨️ Drukuj / zapisz PDF</button>"
            f"<span class='muted small'>W oknie drukowania wybierz „Zapisz jako PDF”, aby zapisać plik.</span></div>"
            f"{body}</body></html>")


def print_presence(q):
    esc = html.escape
    d = presence()
    rows = "".join(f"<tr><td class='check'></td><td>{esc(p['name'] or 'bez nazwy')}</td><td>{esc(p['dept'] or '—')}</td>"
                   f"<td>{esc(p['card'])}</td><td>{esc(p['since'][11:16])}"
                   f"{'' if p['since'][:10] == d['generated'][:10] else ' (' + esc(p['since'][:10]) + ')'}</td></tr>"
                   for p in d["inside"]) or "<tr><td colspan='5' class='muted'>Nikogo nie ma w środku.</td></tr>"
    body = (f"<h1>Lista osób w budynku ({d['count']})</h1><div class='muted'>{esc(d['controller'])} · stan na "
            f"{esc(d['generated'])} · drzwi: {', '.join('#' + str(x) for x in d['doors'])}</div>"
            "<table><thead><tr><th class='check'>✓</th><th>Pracownik</th><th>Dział</th><th>Karta</th><th>W środku od</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
            "<p class='small muted'>Lista według ostatnich odbić kart (wejście bez wyjścia w ciągu 16 h). Osoby, które wyszły bez "
            "odbicia karty albo weszły razem z kimś, mogą być pokazane błędnie - sprawdź obecność na miejscu zbiórki.</p>")
    return f"lista-obecnych_{time.strftime('%Y-%m-%d_%H%M')}", _print_page("Lista osób w budynku", body)


def print_worktime(q):
    esc = html.escape
    try:
        month = datetime.datetime.strptime(_b(q, "month") or datetime.date.today().strftime("%Y-%m"), "%Y-%m").date()
    except ValueError:
        raise ControllerError("Nieprawidłowy miesiąc")
    last = (month.replace(day=28) + datetime.timedelta(days=4)).replace(day=1) - datetime.timedelta(days=1)
    rep = worktime({"from": [month.isoformat()], "to": [last.isoformat()], "card": [_b(q, "card")],
                    "dept": [_b(q, "dept")], "place": [_b(q, "place", "all")]})
    pages = []
    free = {datetime.date.fromisoformat(k): v for k, v in rep["free"].items()}
    for r in rep["rows"]:
        by_day = {d["date"]: d for d in r["days"]}
        trs = []
        for i in range((last - month).days + 1):
            day = month + datetime.timedelta(days=i)
            d = by_day.get(day.isoformat()) or {"sessions": [], "stray": [], "seconds": 0, "overtime": 0, "late": 0}
            notes = []
            if day in free:
                notes.append(free[day])
            if d.get("late"):
                notes.append(f"spóźnienie {d['late']} min")
            if day.isoformat() in r["absent"]:
                notes.append("brak odbić")
            for s_ in d["sessions"]:
                if s_["state"] == "no_out":
                    notes.append("brak wyjścia")
                notes += [f"korekta: {m['note']}" for m in s_["manual"]]
            if d["stray"]:
                notes.append("brak wejścia")
            ins = "<br>".join(s_["in"][11:16] for s_ in d["sessions"])
            outs = "<br>".join((s_["out"][11:16] if s_["state"] == "ok" else "…" if s_["state"] == "ongoing" else "?")
                               for s_ in d["sessions"])
            cls = " class='free'" if day.weekday() >= 5 or day in free else ""
            trs.append(f"<tr{cls}><td>{day.strftime('%d.%m')}</td><td>{WEEKDAY_NAMES[day.weekday()]}</td><td>{ins}</td>"
                       f"<td>{outs}</td><td class='num'>{_hm(d['seconds']) if d['seconds'] else ''}</td>"
                       f"<td class='num'>{_hm(d['overtime']) if d.get('overtime') else ''}</td>"
                       f"<td class='small'>{esc('; '.join(notes))}</td></tr>")
        summary = [f"Przepracowano: <b>{_hm(r['seconds'])}</b>", f"Dni z pracą: <b>{r['days_worked']}</b>",
                   f"Nadgodziny: <b>{_hm(r['overtime'])}</b>"]
        if r["balance"] is not None:
            summary += [f"Norma: <b>{_hm(r['norm_seconds'])}</b> ({rep['work_days']} dni × {_hm(r['norm_day'])})",
                        f"Saldo: <b>{_hm(r['balance'])}</b>"]
        if r["late_count"]:
            summary.append(f"Spóźnienia: <b>{r['late_count']}</b> ({r['late_minutes']} min)")
        if r["absent"]:
            summary.append(f"Dni robocze bez odbić: <b>{len(r['absent'])}</b>")
        pages.append(
            f"<div class='page'><h1>Ewidencja czasu pracy - {month.strftime('%m.%Y')}</h1>"
            f"<div><b>{esc(r['name'] or 'bez nazwy')}</b> · karta {esc(r['card'])}"
            f"{' · dział ' + esc(r['dept']) if r['dept'] else ''}"
            f"{' · początek zmiany ' + esc(r['shift_start']) if r['shift_start'] else ''}</div>"
            f"<div class='muted small'>{esc(rep['controller'])} · wygenerowano {esc(rep['generated'])}</div>"
            "<table><thead><tr><th>Data</th><th>Dzień</th><th>Wejście</th><th>Wyjście</th><th>Czas</th><th>Nadgodziny</th>"
            f"<th>Uwagi</th></tr></thead><tbody>{''.join(trs)}</tbody></table><div class='sum'>{' · '.join(summary)}</div>"
            "<div class='sign'><div>podpis pracownika</div><div>podpis przełożonego</div></div></div>")
    body = "".join(pages) or "<p>Brak pracowników dla wybranych filtrów.</p>"
    return f"czas-pracy_{month.strftime('%Y-%m')}", _print_page(f"Ewidencja czasu pracy {month.strftime('%m.%Y')}", body)


# --- obsługa w tle: automatyczne łączenie, zegar kontrolerów, kopie zapasowe ------------
BACKUP_DIR = os.path.join(DATA_DIR, "kopie")
_MAINT = {"clock": {}, "backup": {"last": "", "result": "", "files": 0}, "autoconnect": {}}
_AUTOCONNECT_NEXT = {}      # id zapisanego kontrolera -> (kiedy następna próba, liczba prób)
_STARTED = time.time()


def _autoconnect_round():
    if time.time() - _STARTED < AUTOCONNECT_DELAY:
        return
    with SAVED_LOCK:
        try:
            items = _saved_load()
        except ControllerError:
            return
    conns = connected()
    for e in items:
        # tryb offline: panel uruchamia się po to, żeby sięgnąć do kontrolera - łączy się z każdym
        # zapisanym z hasłem, bez czekania na zaznaczone „Łącz sam”
        if not e.get("pwd") or not (OFFLINE or e.get("autoconnect")) or e["id"] in _MANUAL_OFF:
            continue
        if any((e.get("device_no") and c.info.get("device_no") == e.get("device_no")) or c.host == e.get("host")
               for c in conns):
            _AUTOCONNECT_NEXT.pop(e["id"], None)
            continue
        when, tries = _AUTOCONNECT_NEXT.get(e["id"], (0, 0))
        # nieudane połączenie zużywa miejsce na połączenie TCP kontrolera - kolejne próby coraz rzadziej
        if time.time() < when or online_public(e["id"]).get("state") == "offline":
            continue
        try:
            saved_connect(e["id"], fallback=False)
            _AUTOCONNECT_NEXT.pop(e["id"], None)
            _MAINT["autoconnect"][e["id"]] = {"at": _now_str(), "result": "połączono"}
            audit("Automatyczne połączenie z kontrolerem", e.get("name") or e.get("host"), ctrl=e.get("name") or e.get("host"))
        except Exception as ex:
            _AUTOCONNECT_NEXT[e["id"]] = (time.time() + min(90 * 3 ** tries, 3600), tries + 1)
            _MAINT["autoconnect"][e["id"]] = {"at": _now_str(), "result": f"błąd: {ex}"}
            _devlog(f"AUTOCONNECT {e.get('host')} błąd: {ex}")


def _clock_round(cfg):
    if not cfg.get("clock_sync"):
        return
    for c in connected():
        key = ctrl_key(c)
        st = _MAINT["clock"].setdefault(key, {"checked": 0})
        if time.time() - st["checked"] < float(cfg.get("clock_check_hours") or 6) * 3600:
            continue
        st["checked"] = time.time()
        name = saved_name(c) or c.host
        try:
            try:
                drift = (c.udp().clock(quiet=True) - datetime.datetime.now()).total_seconds()
            except (ControllerError, OSError):
                drift = _clock_drift(c.status()["clock"], time.strftime("%Y-%m-%d %H:%M:%S"))
            st.update(at=_now_str(), drift=None if drift is None else round(drift))
            if drift is not None and abs(drift) > float(cfg.get("clock_max_drift") or 5):
                if c.auto:
                    st["result"] = "pominięto - trwa auto-dodawanie kart"
                    st["checked"] = time.time() - 3600 * 24
                    continue
                r = c.adjust_time()
                st["result"] = f"zsynchronizowano (różnica była {round(drift)} s)"
                audit("Automatyczna synchronizacja zegara", f"różnica {round(drift)} s, po synchronizacji {r['drift']} s", ctrl=name)
            else:
                st["result"] = "zgodny" if drift is not None else "nie odczytano zegara"
        except Exception as ex:
            st.update(at=_now_str(), result=f"błąd: {ex}")
            audit("Automatyczna synchronizacja zegara", "", ok=False, error=str(ex), ctrl=name)


def _safe_label(text):
    label = unicodedata.normalize("NFKD", (text or "").replace("ł", "l").replace("Ł", "L")).encode("ascii", "ignore").decode()
    return re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-") or "kontroler"


def backup_run(manual=False):
    cfg = setting("maintenance")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp, done, errors = time.strftime("%Y-%m-%d_%H%M"), [], []
    try:
        dst = sqlite3.connect(os.path.join(BACKUP_DIR, f"baza-panelu_{stamp}.db"))
        with _DB_LOCK:
            src = sqlite3.connect(DB_FILE)
            try:
                src.backup(dst)
            finally:
                src.close()
        dst.close()
        done.append("baza panelu")
    except Exception as ex:
        errors.append(f"baza panelu: {ex}")
    for c in connected():
        name = saved_name(c) or c.host
        try:
            _, text = users_backup_file(c)
            with open(os.path.join(BACKUP_DIR, f"uzytkownicy_{_safe_label(name)}_{stamp}.json"), "w", encoding="utf-8") as f:
                f.write(text)
            done.append(name)
        except Exception as ex:
            errors.append(f"{name}: {ex}")
    keep = max(1, int(cfg.get("backup_keep") or 14))
    groups = {}
    for fn in os.listdir(BACKUP_DIR):
        m = re.fullmatch(r"(.+)_\d{4}-\d{2}-\d{2}_\d{4}\.(db|json)", fn)
        if m:
            groups.setdefault(m.group(1), []).append(fn)
    for files in groups.values():
        for fn in sorted(files)[:-keep]:
            with contextlib.suppress(OSError):
                os.remove(os.path.join(BACKUP_DIR, fn))
    result = ("kopia: " + ", ".join(done) if done else "") + ("; błędy: " + "; ".join(errors) if errors else "")
    _MAINT["backup"].update(last=_now_str(), result=result or "brak danych do kopii")
    audit("Kopia zapasowa" + (" (ręcznie)" if manual else " (automatyczna)"), ", ".join(done), ok=not errors,
          error="; ".join(errors), ctrl="")
    return {"ok": not errors, "msg": _MAINT["backup"]["result"]}


def backups_list():
    try:
        files = sorted(os.listdir(BACKUP_DIR), reverse=True)
    except OSError:
        files = []
    out = []
    for fn in files:
        path = os.path.join(BACKUP_DIR, fn)
        if os.path.isfile(path) and re.fullmatch(r"[A-Za-z0-9_.-]+\.(db|json)", fn):
            out.append({"name": fn, "size": os.path.getsize(path),
                        "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(path)))})
    return out


def backup_file(name):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(db|json)", name or "") or ".." in name:
        raise ControllerError("Nieprawidłowa nazwa pliku")
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(path):
        raise ControllerError("Nie ma takiej kopii")
    with open(path, "rb") as f:
        return f.read()


def _backup_round(cfg):
    if not cfg.get("backup"):
        return
    try:
        at = _hhmm(cfg.get("backup_time") or "02:30")
    except ControllerError:
        at = "02:30"
    today = time.strftime("%Y-%m-%d")
    if not _MAINT["backup"]["last"]:
        # po restarcie panelu: dzisiejsza kopia mogła już powstać
        newest = next((f["time"] for f in backups_list() if f["name"].startswith("baza-panelu_")), "")
        _MAINT["backup"]["last"] = newest if newest.startswith(today) else "-"
    if time.strftime("%H:%M") >= at and not _MAINT["backup"]["last"].startswith(today):
        backup_run()


def _cleanup_round():
    today = time.strftime("%Y-%m-%d")
    if _MAINT.get("cleanup") == today:
        return
    _MAINT["cleanup"] = today
    now = datetime.datetime.now()
    with db() as con:
        con.execute("DELETE FROM audit WHERE time < ?", ((now - datetime.timedelta(days=730)).strftime("%Y-%m-%d"),))
        con.execute("DELETE FROM live_events WHERE time < ?", ((now - datetime.timedelta(days=120)).strftime("%Y-%m-%d"),))
        con.execute("DELETE FROM notify_log WHERE time < ?", ((now - datetime.timedelta(days=365)).strftime("%Y-%m-%d"),))


# -- czyszczenie logów przez administratora --
# Firmware kontrolera nie ma czyszczenia logu (docs/PROTOCOL.md), więc czyścimy tylko to, co trzyma panel.
# Log przejść to kopia logu kontrolera: bez znacznika sync_state.cleared_to następne pobranie ściągnęłoby
# usunięte wpisy z powrotem, dlatego _store_swipes pomija wszystko, co nie jest nowsze od znacznika.
LOG_KINDS = {
    "swipes": ("Log przejść", "swipes", True),
    "live": ("Zdarzenia na żywo", "live_events", True),
    "audit": ("Dziennik działań", "audit", False),
    "notify": ("Historia powiadomień", "notify_log", False),
}


def _ctrl_names():
    with SAVED_LOCK:
        try:
            items = _saved_load()
        except ControllerError:
            items = []
    names = {}
    for e in items:
        if e.get("device_no"):
            names[f"dev:{e['device_no']}"] = e.get("name") or e.get("host", "")
        if e.get("host"):
            names.setdefault(f"ip:{e['host']}", e.get("name") or e["host"])
    for c in connected():
        names.setdefault(ctrl_key(c), saved_name(c) or c.host)
    return names


def _logs_scope(kinds, ctrl, before):
    kinds = [k for k in (kinds or "").split(",") if k in LOG_KINDS]
    if not kinds:
        raise ControllerError("Wybierz, które logi wyczyścić")
    day = _day(before) if before else None
    if before and not day:
        raise ControllerError("Nieprawidłowa data")
    if day and day > datetime.date.today():
        raise ControllerError("Data nie może być z przyszłości - żeby usunąć wszystko, wybierz „cały log”")
    return kinds, (ctrl or "").strip(), day


def _logs_where(kind, ctrl, day):
    where, args = [], []
    if ctrl and LOG_KINDS[kind][2]:
        where.append("ctrl = ?")
        args.append(ctrl)
    if day:
        where.append("time < ?")
        args.append(f"{day.isoformat()} 00:00:00")
    return (" WHERE " + " AND ".join(where)) if where else "", args


def logs_state(q=None):
    names = _ctrl_names()
    with db() as con:
        kinds, ctrls = [], set()
        for k, (label, table, per_ctrl) in LOG_KINDS.items():
            r = con.execute(f"SELECT COUNT(*), MIN(time), MAX(time) FROM {table}").fetchone()
            kinds.append({"id": k, "label": label, "count": r[0], "oldest": r[1] or "", "newest": r[2] or "",
                          "per_ctrl": per_ctrl})
            if per_ctrl:
                ctrls |= {x[0] for x in con.execute(f"SELECT DISTINCT ctrl FROM {table}")}
        cleared = {r[0]: r[1] for r in con.execute("SELECT ctrl, cleared_to FROM sync_state WHERE cleared_to <> ''")}
    return {"kinds": kinds, "cleared": [{"ctrl": k, "name": names.get(k, k), "to": v} for k, v in sorted(cleared.items())],
            "ctrls": sorted(({"key": k, "name": names.get(k, k)} for k in ctrls),
                            key=lambda x: x["name"].lower())}


def logs_preview(kinds, ctrl, before):
    kinds, ctrl, day = _logs_scope(kinds, ctrl, before)
    out = []
    with db() as con:
        for k in kinds:
            where, args = _logs_where(k, ctrl, day)
            n = con.execute(f"SELECT COUNT(*) FROM {LOG_KINDS[k][1]}{where}", args).fetchone()[0]
            out.append({"id": k, "label": LOG_KINDS[k][0], "count": n})
    return {"rows": out, "total": sum(x["count"] for x in out)}


def logs_clear(kinds, ctrl, before):
    kinds, ctrl, day = _logs_scope(kinds, ctrl, before)
    names = _ctrl_names()
    scope = ("wszystko" if not day else f"starsze niż {day.isoformat()}") + \
        (f", kontroler: {names.get(ctrl, ctrl)}" if ctrl else "")
    # kopia bazy przed usunięciem - to jedyna droga powrotu (wpisów sprzed znacznika panel już nie pobierze)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    copy = f"przed-czyszczeniem-logow_{time.strftime('%Y-%m-%d_%H%M%S')}.db"
    try:
        dst = sqlite3.connect(os.path.join(BACKUP_DIR, copy))
        with _DB_LOCK:
            src = sqlite3.connect(DB_FILE)
            try:
                src.backup(dst)
            finally:
                src.close()
        dst.close()
    except Exception as e:
        audit("Czyszczenie logów", scope, ok=False, error=f"kopia bazy: {e}", ctrl="")
        raise ControllerError(f"Nie udało się zrobić kopii bazy przed czyszczeniem ({e}) - niczego nie usunięto")
    done = []
    with db() as con:
        for k in kinds:
            label, table, _ = LOG_KINDS[k]
            where, args = _logs_where(k, ctrl, day)
            if k == "swipes":
                keys = [ctrl] if ctrl else [r[0] for r in con.execute(
                    "SELECT ctrl FROM swipes UNION SELECT ctrl FROM sync_state")]
                for key in keys:
                    if day:
                        mark = f"{(day - datetime.timedelta(days=1)).isoformat()} 23:59:59"
                    else:
                        newest = con.execute("SELECT MAX(time) FROM swipes WHERE ctrl = ?", (key,)).fetchone()[0] or ""
                        mark = max(_now_str(), newest)
                    con.execute("INSERT INTO sync_state(ctrl, full_done, cleared_to) VALUES (?, 0, ?) "
                                "ON CONFLICT(ctrl) DO UPDATE SET cleared_to = MAX(cleared_to, excluded.cleared_to)",
                                (key, mark))
                # wyjątki „wejście po godzinach” są dopiskami do logu przejść
                con.execute(f"DELETE FROM entry_passes{where}", args)
            n = con.execute(f"DELETE FROM {table}{where}", args).rowcount
            done.append(f"{label.lower()}: {n}")
    with contextlib.suppress(Exception):
        with db() as con:
            con.execute("VACUUM")
    groups = sorted(fn for fn in os.listdir(BACKUP_DIR) if fn.startswith("przed-czyszczeniem-logow_"))
    for fn in groups[:-5]:
        with contextlib.suppress(OSError):
            os.remove(os.path.join(BACKUP_DIR, fn))
    # wpis trafia do dziennika PO czyszczeniu, więc zostaje nawet po wyczyszczeniu dziennika
    audit("Czyszczenie logów", f"{scope}; usunięto {', '.join(done)}; kopia: {copy}", ctrl="")
    return {"ok": True, "msg": f"Usunięto - {', '.join(done)}. Kopia bazy sprzed czyszczenia: {copy}",
            "state": logs_state()}


def _maintenance_loop():
    # w trybie offline pierwsze podejście od razu: panel uruchomiono po to, żeby sięgnąć do kontrolera,
    # więc nie każemy czekać 20 s na automatyczne połączenie
    wait = 1 if OFFLINE else 20
    while True:
        time.sleep(wait)
        wait = 20
        for fn in (_autoconnect_round, lambda: _clock_round(setting("maintenance")),
                   lambda: _backup_round(setting("maintenance")), _cleanup_round):
            try:
                fn()
            except Exception as ex:
                _devlog(f"MAINT błąd: {type(ex).__name__}: {ex}")


def maintenance_state():
    cfg = setting("maintenance")
    clocks = []
    for c in connected():
        st = _MAINT["clock"].get(ctrl_key(c), {})
        clocks.append({"name": saved_name(c) or c.host, "at": st.get("at", ""), "drift": st.get("drift"),
                       "result": st.get("result", "jeszcze nie sprawdzano")})
    with SAVED_LOCK:
        try:
            saved = {e["id"]: e.get("name") or e.get("host") for e in _saved_load()}
        except ControllerError:
            saved = {}
    auto = [{"name": saved.get(k, k), **v} for k, v in _MAINT["autoconnect"].items()]
    return {"settings": cfg, "clocks": clocks, "backup": _MAINT["backup"], "files": backups_list(),
            "backup_dir": BACKUP_DIR, "autoconnect": auto}


def maintenance_save(raw):
    try:
        new = json.loads(raw or "{}")
    except ValueError:
        raise ControllerError("Nieprawidłowe ustawienia")
    cfg = _merge(SETTINGS_DEFAULTS["maintenance"], new)
    try:
        cfg["clock_max_drift"] = max(2, min(600, int(cfg["clock_max_drift"])))
        cfg["clock_check_hours"] = max(1, min(168, int(cfg["clock_check_hours"])))
        cfg["backup_keep"] = max(1, min(365, int(cfg["backup_keep"])))
        cfg["backup_time"] = _hhmm(cfg["backup_time"])
    except (TypeError, ValueError):
        raise ControllerError("Nieprawidłowa liczba w ustawieniach")
    cfg["clock_sync"], cfg["backup"] = bool(cfg["clock_sync"]), bool(cfg["backup"])
    setting_save("maintenance", cfg)
    for st in _MAINT["clock"].values():
        st["checked"] = 0                       # sprawdź zegary wkrótce według nowych ustawień
    return dict(maintenance_state(), ok=True)


# --- konta panelu, sesje, dziennik działań --------------------------------------
# Panel otwiera drzwi i zmienia ustawienia kontrolerów, więc wymaga logowania. Role:
#   viewer (podgląd)   - pulpit, log, obecni, czas pracy (bez zmian),
#   operator           - do tego otwieranie drzwi, karty (dodawanie, ważność, blokady), działy, korekty czasu pracy,
#   admin              - wszystko: godziny wejścia, hasła, system kontrolera, połączenia, konta panelu, ustawienia.
# Hasła: PBKDF2-SHA256. Sesja w ciasteczku HttpOnly + SameSite=Strict; zapytania zmieniające stan muszą mieć
# nagłówek X-ACB (formularz z obcej strony go nie wyśle). Pierwsze konto administratora: z tego samego komputera
# bez kodu, z sieci - z kodem wypisanym w konsoli i w pliku w katalogu danych (albo ACS_ADMIN_LOGIN/PASSWORD).
ROLES = {"viewer": 1, "operator": 2, "admin": 3}
ROLE_NAMES = {"viewer": "Podgląd", "operator": "Operator", "admin": "Administrator"}
PWD_MIN = 8
AUTH_DISABLED = os.environ.get("ACS_AUTH", "") == "0" and LISTEN_HOST in ("127.0.0.1", "localhost", "::1")
COOKIE = "acb_panel_sid"
SETUP_FILE = os.path.join(DATA_DIR, "kod-pierwszego-logowania.txt")
_SETUP = {"code": None}
_SESSIONS = {}              # skrót tokenu -> sesja (wiersz panel_sessions + konto)
_SESS_LOCK = threading.Lock()
_LOGIN_FAIL = {}            # "ip:..." / "login:..." -> [nieudane próby, zablokowane do]
LOCAL_SESSION = {"token": "local", "user_id": 0, "login": "lokalny", "name": "Użytkownik lokalny",
                 "role": "admin", "active": 1, "ctrl": "", "created": 0, "seen": 0}


class AuthError(ControllerError):
    def __init__(self, msg, code=401):
        super().__init__(msg)
        self.code = code


def pwd_hash(pwd, salt=None, rounds=200000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), bytes.fromhex(salt), rounds).hex()
    return f"pbkdf2_sha256${rounds}${salt}${h}"


def pwd_check(pwd, stored):
    try:
        algo, rounds, salt, _ = stored.split("$")
        return algo == "pbkdf2_sha256" and hmac.compare_digest(pwd_hash(pwd, salt, int(rounds)), stored)
    except (ValueError, TypeError, AttributeError):
        return False


def _token_key(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def session_create(user, ip, agent):
    token, now = secrets.token_urlsafe(32), time.time()
    with db() as con:
        con.execute("DELETE FROM panel_sessions WHERE seen < ? OR created < ?", (now - SESSION_IDLE, now - SESSION_MAX))
        con.execute("INSERT INTO panel_sessions(token, user_id, created, seen, ip, agent) VALUES (?, ?, ?, ?, ?, ?)",
                    (_token_key(token), user["id"], now, now, ip, (agent or "")[:200]))
        con.execute("UPDATE panel_users SET last_login = ? WHERE id = ?", (_now_str(), user["id"]))
    return token


def session_get(token):
    if not token:
        return None
    key, now = _token_key(token), time.time()
    with _SESS_LOCK:
        sess = _SESSIONS.get(key)
    if sess is None:
        with db() as con:
            r = con.execute("SELECT s.token, s.user_id, s.created, s.seen, s.ctrl, u.login, u.name, u.role, u.active "
                            "FROM panel_sessions s JOIN panel_users u ON u.id = s.user_id WHERE s.token = ?",
                            (key,)).fetchone()
        if r is None:
            return None
        sess = dict(r, _saved=now)
    if not sess["active"] or now - sess["seen"] > SESSION_IDLE or now - sess["created"] > SESSION_MAX:
        session_drop(key)
        return None
    sess["seen"] = now
    if now - sess["_saved"] > 60:
        sess["_saved"] = now
        with db() as con:
            con.execute("UPDATE panel_sessions SET seen = ? WHERE token = ?", (now, key))
    with _SESS_LOCK:
        _SESSIONS[key] = sess
    return sess


def session_drop(key):
    with _SESS_LOCK:
        _SESSIONS.pop(key, None)
    with db() as con:
        con.execute("DELETE FROM panel_sessions WHERE token = ?", (key,))


def sessions_forget(user_id, drop=False, keep=None):
    """Po zmianie konta: sesje przeczytają je ponownie z bazy; `drop` - wyloguj (poza sesją `keep`)."""
    with _SESS_LOCK:
        for k in [k for k, v in _SESSIONS.items() if v["user_id"] == user_id]:
            del _SESSIONS[k]
    if drop:
        with db() as con:
            con.execute("DELETE FROM panel_sessions WHERE user_id = ? AND token <> ?", (user_id, keep or ""))


def session_select(sess, key):
    sess["ctrl"] = key
    if sess.get("token") != "local":
        with db() as con:
            con.execute("UPDATE panel_sessions SET ctrl = ? WHERE token = ?", (key, sess["token"]))


def _fail(keys):
    now = time.time()
    if len(_LOGIN_FAIL) > 5000:          # stare wpisy (np. skanowanie z wielu adresów) - nie trzymaj w nieskończoność
        for k in [k for k, v in _LOGIN_FAIL.items() if v[1] < now - 3600]:
            del _LOGIN_FAIL[k]
    for k in keys:
        st = _LOGIN_FAIL.setdefault(k, [0, 0])
        st[0] += 1
        if st[0] >= 5:
            st[1] = now + min(60 * 2 ** (st[0] - 5), 900)


def _check_lock(keys):
    now = time.time()
    for k in keys:
        st = _LOGIN_FAIL.get(k)
        if st and st[1] > now:
            raise AuthError(f"Za dużo nieudanych prób logowania - spróbuj ponownie za {int(st[1] - now) + 1} s", 429)


def needs_setup():
    with db() as con:
        return con.execute("SELECT COUNT(*) FROM panel_users").fetchone()[0] == 0


def _setup_help():
    """Gdzie osoba zakładająca pierwsze konto znajdzie kod: pełna ścieżka pliku, system, okno konsoli albo log
    (panel uruchomiony w tle ma wyjście przekierowane do pliku - na Linuksie jego ścieżka jest w /proc)."""
    try:
        console = sys.stdout.isatty()
    except (AttributeError, ValueError):
        console = False
    log = ""
    if not console:
        with contextlib.suppress(OSError):
            target = os.readlink("/proc/self/fd/1")
            log = target if target.startswith("/") and not target.startswith("/dev/") else ""
    local = ""
    if LISTEN_HOST in ("0.0.0.0", "", "::") and _SETUP.get("port"):
        local = f"{_SETUP.get('scheme', 'http')}://127.0.0.1:{_SETUP['port']}"
    return {"file": SETUP_FILE, "os": "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux",
            "console": console, "log": log, "local_url": local}


def auth_state():
    sess = getattr(_REQ, "session", None)
    setup = not AUTH_DISABLED and needs_setup()
    local = bool(getattr(_REQ, "local", False))
    return {"auth": not AUTH_DISABLED, "needs_setup": setup, "local": local, "roles": ROLE_NAMES, "version": APP_VERSION,
            "mode": PANEL_MODE, "offline_off": OFFLINE_OFF, "offline_why": OFFLINE_WHY,
            "setup_help": _setup_help() if setup and not local else None,
            "user": ({"login": sess["login"], "name": sess["name"], "role": sess["role"],
                      "role_name": ROLE_NAMES.get(sess["role"], sess["role"])} if sess else None)}


def login(user_login, pwd, ip, agent):
    user_login = (user_login or "").strip()
    keys = [f"ip:{ip}", f"login:{user_login.lower()}"]
    _check_lock(keys)
    with db() as con:
        u = con.execute("SELECT * FROM panel_users WHERE login = ?", (user_login,)).fetchone()
    if u is None:
        pwd_check(pwd or "", pwd_hash("x"))     # podobny czas odpowiedzi dla nieistniejącego loginu
    if u is None or not u["active"] or not pwd_check(pwd or "", u["pwd"]):
        _fail(keys)
        audit("Nieudane logowanie", f"login „{user_login[:40]}”", ok=False, login=user_login[:40], ip=ip)
        raise AuthError("Nieprawidłowy login lub hasło")
    for k in keys:
        _LOGIN_FAIL.pop(k, None)
    token = session_create(u, ip, agent)
    audit("Logowanie", "", login=u["login"], ip=ip)
    return token


def _login_name(v):
    v = (v or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._@-]{2,40}", v):
        raise ControllerError("Login: 2–40 znaków - litery bez polskich znaków, cyfry, kropka, myślnik, _ lub @")
    return v


def _pwd_new(pwd):
    if len(pwd or "") < PWD_MIN:
        raise ControllerError(f"Hasło musi mieć co najmniej {PWD_MIN} znaków")
    return pwd


def setup_prepare():
    """Przy starcie: konto ze zmiennych środowiskowych albo kod do utworzenia pierwszego konta."""
    if AUTH_DISABLED:
        return
    env_login, env_pwd = os.environ.get("ACS_ADMIN_LOGIN", ""), os.environ.get("ACS_ADMIN_PASSWORD", "")
    if needs_setup() and env_login and env_pwd:
        panel_user_save("", env_login, "Administrator", "admin", env_pwd, True, system=True)
        print(f"Utworzono konto administratora panelu „{env_login}” (ACS_ADMIN_LOGIN).")
    if needs_setup():
        _SETUP["code"] = f"{secrets.randbelow(10 ** 8):08d}"
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            fd = os.open(SETUP_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"Kod do utworzenia pierwszego konta administratora panelu ACB: {_SETUP['code']}\n"
                        "Na komputerze z panelem kod nie jest potrzebny. Plik zniknie po utworzeniu konta.\n")
        except OSError:
            pass
    elif os.path.exists(SETUP_FILE):
        with contextlib.suppress(OSError):
            os.remove(SETUP_FILE)


def setup_admin(b, ip, agent, local):
    if not needs_setup():
        raise AuthError("Konto administratora już istnieje - zaloguj się", 409)
    keys = [f"ip:{ip}"]
    _check_lock(keys)
    if not local and not hmac.compare_digest(_b(b, "code").strip(), _SETUP["code"] or "-"):
        _fail(keys)
        raise AuthError("Nieprawidłowy kod. Aktualny kod jest w pliku " + SETUP_FILE
                        + " na komputerze, na którym działa panel (kod zmienia się przy każdym uruchomieniu panelu)", 403)
    uid = panel_user_save("", _b(b, "login"), _b(b, "name"), "admin", _b(b, "pwd"), True, system=True)["id"]
    _SETUP["code"] = None
    with contextlib.suppress(OSError):
        os.remove(SETUP_FILE)
    with db() as con:
        u = con.execute("SELECT * FROM panel_users WHERE id = ?", (uid,)).fetchone()
    audit("Utworzenie pierwszego konta administratora", u["login"], login=u["login"], ip=ip)
    return session_create(u, ip, agent)


def panel_users_list():
    with db() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT u.id, u.login, u.name, u.role, u.active, u.created, u.last_login, "
            "(SELECT COUNT(*) FROM panel_sessions s WHERE s.user_id = u.id AND s.seen > ?) AS sessions "
            "FROM panel_users u ORDER BY u.login COLLATE NOCASE", (time.time() - SESSION_IDLE,))]
    sess = getattr(_REQ, "session", None)
    for r in rows:
        r["me"] = bool(sess) and r["id"] == sess.get("user_id")
    return {"users": rows, "roles": ROLE_NAMES}


def _other_admins(con, uid):
    return con.execute("SELECT COUNT(*) FROM panel_users WHERE role = 'admin' AND active = 1 AND id <> ?",
                       (uid or 0,)).fetchone()[0]


def panel_user_save(uid, user_login, name, role, pwd, active, system=False):
    user_login, name = _login_name(user_login), (name or "").strip()[:60]
    if role not in ROLES:
        raise ControllerError("Nieprawidłowa rola")
    uid = int(uid) if str(uid or "").isdigit() else None
    sess = getattr(_REQ, "session", None)
    with db() as con:
        if uid is None:
            try:
                cur = con.execute("INSERT INTO panel_users(login, name, role, pwd, active, created) VALUES (?, ?, ?, ?, ?, ?)",
                                  (user_login, name, role, pwd_hash(_pwd_new(pwd)), int(bool(active)), _now_str()))
            except sqlite3.IntegrityError:
                raise ControllerError(f"Konto „{user_login}” już istnieje")
            uid = cur.lastrowid
        else:
            old = con.execute("SELECT * FROM panel_users WHERE id = ?", (uid,)).fetchone()
            if old is None:
                raise ControllerError("Nie znaleziono konta")
            if old["role"] == "admin" and (role != "admin" or not active) and not _other_admins(con, uid):
                raise ControllerError("To jedyne aktywne konto administratora - nie można mu odebrać uprawnień")
            if not system and sess and sess.get("user_id") == uid and not active:
                raise ControllerError("Nie możesz wyłączyć własnego konta")
            try:
                con.execute("UPDATE panel_users SET login = ?, name = ?, role = ?, active = ? WHERE id = ?",
                            (user_login, name, role, int(bool(active)), uid))
            except sqlite3.IntegrityError:
                raise ControllerError(f"Konto „{user_login}” już istnieje")
            if pwd:
                con.execute("UPDATE panel_users SET pwd = ? WHERE id = ?", (pwd_hash(_pwd_new(pwd)), uid))
    keep = sess.get("token") if sess and sess.get("user_id") == uid else None
    sessions_forget(uid, drop=bool(pwd) or not active, keep=keep)
    return {"ok": True, "id": uid}


def panel_user_delete(uid):
    uid = int(uid) if str(uid or "").isdigit() else 0
    sess = getattr(_REQ, "session", None)
    if sess and sess.get("user_id") == uid:
        raise ControllerError("Nie możesz usunąć własnego konta")
    with db() as con:
        u = con.execute("SELECT * FROM panel_users WHERE id = ?", (uid,)).fetchone()
        if u is None:
            raise ControllerError("Nie znaleziono konta")
        if u["role"] == "admin" and u["active"] and not _other_admins(con, uid):
            raise ControllerError("To jedyne aktywne konto administratora")
        con.execute("DELETE FROM panel_users WHERE id = ?", (uid,))
    sessions_forget(uid, drop=True)
    return {"ok": True, "login": u["login"]}


def own_password(old, new):
    sess = getattr(_REQ, "session", None)
    if not sess or sess.get("token") == "local":
        raise ControllerError("Logowanie do panelu jest wyłączone")
    with db() as con:
        u = con.execute("SELECT * FROM panel_users WHERE id = ?", (sess["user_id"],)).fetchone()
        if u is None or not pwd_check(old or "", u["pwd"]):
            raise ControllerError("Obecne hasło jest nieprawidłowe")
        con.execute("UPDATE panel_users SET pwd = ? WHERE id = ?", (pwd_hash(_pwd_new(new)), u["id"]))
    sessions_forget(u["id"], drop=True, keep=sess["token"])
    return {"ok": True, "msg": "Zmieniono hasło - inne sesje tego konta zostały wylogowane"}


def audit(action, details="", ok=True, error="", ctrl=None, login=None, ip=None):
    sess = getattr(_REQ, "session", None)
    if ctrl is None:
        c = current_controller() if sess is not None else None
        ctrl = (saved_name(c) or c.host) if c is not None else ""
    try:
        with db() as con:
            con.execute("INSERT INTO audit(time, login, ip, action, ctrl, details, ok, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (_now_str(), login if login is not None else (sess["login"] if sess else "system"),
                         ip if ip is not None else getattr(_REQ, "ip", ""), action, ctrl or "", (details or "")[:500],
                         int(bool(ok)), (error or "")[:300]))
    except Exception as e:
        _devlog(f"AUDIT błąd zapisu: {e}")


AUDIT_PAGE = 100


def audit_list(q):
    where, args = ["1 = 1"], []
    if _b(q, "login"):
        where.append("login = ?")
        args.append(_b(q, "login"))
    if _b(q, "q"):
        where.append("(action LIKE ? OR details LIKE ? OR ctrl LIKE ?)")
        args += [f"%{_b(q, 'q')}%"] * 3
    if _day(_b(q, "from")):
        where.append("time >= ?")
        args.append(f"{_day(_b(q, 'from')).isoformat()} 00:00:00")
    if _day(_b(q, "to")):
        where.append("time <= ?")
        args.append(f"{_day(_b(q, 'to')).isoformat()} 23:59:59")
    if _b(q, "errors") == "1":
        where.append("ok = 0")
    try:
        page = max(int(_b(q, "page", "1")), 1)
    except ValueError:
        page = 1
    w = " AND ".join(where)
    with db() as con:
        total = con.execute(f"SELECT COUNT(*) FROM audit WHERE {w}", args).fetchone()[0]
        rows = [dict(r) for r in con.execute(f"SELECT * FROM audit WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                                             args + [AUDIT_PAGE, (page - 1) * AUDIT_PAGE])]
        logins = [r[0] for r in con.execute("SELECT DISTINCT login FROM audit ORDER BY login COLLATE NOCASE")]
    return {"rows": rows, "total": total, "page": page, "pages": max((total + AUDIT_PAGE - 1) // AUDIT_PAGE, 1),
            "logins": logins}


# --- routing -----------------------------------------------------------------
def _b(body, k, d=""):
    return body.get(k, [d])[0]


def _access(b):
    # access = "1,0,1,1" (drzwi po kolei); puste pozycje = bez zmian
    return {i + 1: v == "1" for i, v in enumerate(_b(b, "access").split(",")) if v in ("0", "1")}


def active_state(q):
    c = current_controller()
    return {"active": active_info(c) if c else None, "connected": connected_list(),
            "default_host": DEF_HOST, "default_user": DEF_USER}


# ścieżka -> (funkcja, minimalna rola)
ROUTES_GET = {
    "/api/subnet": (lambda q: {"subnet": local_subnet()}, "admin"),
    "/api/active": (active_state, "viewer"),
    "/api/saved": (lambda q: saved_list(), "viewer"),
    "/api/status": (lambda q: (require_active().status(), active_info())[1], "viewer"),
    "/api/users": (lambda q: users_with_departments(_b(q, "q")), "viewer"),
    "/api/swipe": (lambda q: require_active().swipe(_b(q, "nav", None)), "viewer"),
    "/api/swipe/sync": (lambda q: _sync_public(ctrl_key(require_active())), "viewer"),
    "/api/log": (log_local, "viewer"),
    "/api/people": (lambda q: people_list(), "viewer"),
    "/api/people/directory": (lambda q: people_directory(), "viewer"),
    "/api/cards/candidates": (lambda q: card_candidates(_b(q, "name"), _b(q, "card")), "operator"),
    "/api/cards/last-denied": (lambda q: card_last_denied(), "operator"),
    "/api/departments": (lambda q: {"departments": departments()}, "viewer"),
    "/api/tracking": (lambda q: tracking_state(), "viewer"),
    "/api/doors/open": (lambda q: door_watch_config(), "viewer"),
    "/api/entryhours": (lambda q: entry_hours_state(fresh=True), "viewer"),
    "/api/holidays/pl": (pl_holidays_public, "viewer"),
    "/api/worktime": (worktime, "viewer"),
    "/api/work/settings": (lambda q: work_settings(), "viewer"),
    "/api/codes": (lambda q: require_active().read_codes(), "admin"),
    "/api/user": (lambda q: require_active().user_detail(_b(q, "user_id"), _b(q, "card")), "viewer"),
    "/api/backup/restore": (lambda q: restore_state(), "admin"),
    "/api/cards/bulk": (lambda q: bulk_add_state(), "operator"),
    "/api/live": (live, "viewer"),
    "/api/presence": (presence_state, "viewer"),
    "/api/audit": (audit_list, "admin"),
    "/api/panel/users": (lambda q: panel_users_list(), "admin"),
    "/api/notify": (lambda q: notify_settings(), "admin"),
    "/api/maintenance": (lambda q: maintenance_state(), "admin"),
    "/api/logs": (logs_state, "admin"),
}
ROUTES_POST = {
    "/api/discover": (lambda b: discover(_b(b, "subnet", None) or None, _b(b, "user", DEF_USER), _b(b, "pwd", DEF_PWD)), "admin"),
    "/api/connect": (lambda b: connect_public(_b(b, "host"), _b(b, "user"), _b(b, "pwd")), "admin"),
    "/api/setip": (lambda b: wg_set_ip(_b(b, "device_no"), _b(b, "ip"), _b(b, "mask", "255.255.255.0") or "255.255.255.0",
                                       _b(b, "gateway")), "admin"),
    "/api/disconnect": (lambda b: disconnect(_b(b, "key")), "admin"),
    "/api/select": (lambda b: select_controller(_b(b, "key")), "viewer"),
    "/api/saved/save": (lambda b: saved_save_active(_b(b, "name"), _b(b, "remember_pwd") == "1"), "admin"),
    "/api/saved/rename": (lambda b: saved_rename(_b(b, "id"), _b(b, "name")), "admin"),
    "/api/saved/delete": (lambda b: saved_delete(_b(b, "id")), "admin"),
    "/api/saved/connect": (lambda b: saved_connect(_b(b, "id"), _b(b, "pwd")), "operator"),
    "/api/saved/autoconnect": (lambda b: saved_autoconnect(_b(b, "id"), _b(b, "enabled") == "1"), "admin"),
    "/api/saved/check": (lambda b: online_check_now(), "viewer"),
    "/api/swipe/sync": (lambda b: swipe_sync_start(), "viewer"),
    "/api/departments/add": (lambda b: dept_add(_b(b, "name")), "operator"),
    "/api/departments/rename": (lambda b: dept_rename(_b(b, "id"), _b(b, "name")), "operator"),
    "/api/departments/delete": (lambda b: dept_delete(_b(b, "id")), "operator"),
    "/api/people/assign": (lambda b: person_assign(_b(b, "card"), _b(b, "name"), _b(b, "dept_id")), "operator"),
    "/api/people/assign-bulk": (lambda b: people_assign_bulk(_b(b, "cards"), _b(b, "dept_id")), "operator"),
    "/api/people/forget": (lambda b: person_forget(_b(b, "card")), "operator"),
    "/api/tracking": (lambda b: tracking_set(_b(b, "door"), _b(b, "enabled") == "1",
                                             _b(b, "role") if "role" in b else None), "admin"),
    "/api/doors/open": (lambda b: door_watch_set(_b(b, "door"), _b(b, "enabled") == "1", _b(b, "minutes")), "admin"),
    "/api/entryhours": (lambda b: entry_hours_save(_b(b, "config")), "admin"),
    "/api/addcard": (lambda b: add_card_active(_b(b, "card"), _b(b, "name"), _b(b, "valid_from"), _b(b, "valid_to")), "operator"),
    "/api/cards/bulk/preview": (lambda b: bulk_add_preview(_b(b, "list")), "operator"),
    "/api/cards/bulk": (lambda b: bulk_add_start(_b(b, "list"), _b(b, "dept_id"), _b(b, "valid_to")), "operator"),
    "/api/autoadd": (lambda b: require_active().auto_add(), "operator"),
    "/api/autoadd/stop": (lambda b: require_active().auto_add_stop(), "operator"),
    "/api/autoadd/state": (lambda b: require_active().auto_add_state(), "operator"),
    "/api/edituser": (lambda b: edit_user_active(_b(b, "user_id"), b["name"][0] if "name" in b else None, _access(b),
                                                 _b(b, "card")), "operator"),
    "/api/deluser": (lambda b: delete_user_active(_b(b, "user_id"), _b(b, "card")), "operator"),
    "/api/cards/replace": (lambda b: card_replace(_b(b, "user_id"), _b(b, "old"), _b(b, "new")), "operator"),
    "/api/cards/link": (lambda b: card_link(_b(b, "old"), _b(b, "new")), "operator"),
    "/api/card/validity": (lambda b: card_validity(_b(b, "card"), _b(b, "valid_from"), _b(b, "valid_to")), "operator"),
    "/api/card/block": (lambda b: card_block(_b(b, "card"), _b(b, "reason"), _b(b, "everywhere") == "1"), "operator"),
    "/api/card/unblock": (lambda b: card_unblock(_b(b, "card")), "operator"),
    "/api/backup/preview": (lambda b: restore_preview(_b(b, "data")), "admin"),
    "/api/backup/restore": (lambda b: restore_start(_b(b, "data"), _b(b, "cards") == "1", _b(b, "depts") == "1"), "admin"),
    "/api/open": (lambda b: require_active().open_door(_b(b, "door", "1")), "operator"),
    "/api/doorname": (lambda b: require_active().set_door_name(_b(b, "name"), _b(b, "door", "1")), "admin"),
    "/api/doordelay": (lambda b: require_active().set_door_delay(_b(b, "sec"), _b(b, "door", "1")), "admin"),
    "/api/events": (lambda b: require_active().set_events(_b(b, "enabled") == "1"), "admin"),
    "/api/language": (lambda b: require_active().set_language(_b(b, "lang")), "admin"),
    "/api/supercard": (lambda b: require_active().set_super_card(_b(b, "card"), _b(b, "slot", "1")), "admin"),
    "/api/doorpassword": (lambda b: require_active().set_door_password(_b(b, "pwd"), _b(b, "slot", "1"),
                                                                       _b(b, "door", "1")), "admin"),
    "/api/admin": (lambda b: set_admin_active(_b(b, "old_name"), _b(b, "old_pwd"), _b(b, "new_name"), _b(b, "new_pwd")), "admin"),
    "/api/network": (lambda b: set_network_active(_b(b, "ip"), _b(b, "gateway")), "admin"),
    "/api/factoryreset": (lambda b: factory_reset_active(), "admin"),
    "/api/reboot": (lambda b: require_active().reboot(), "admin"),
    "/api/synctime": (lambda b: require_active().adjust_time(), "admin"),
    "/api/work/correction": (lambda b: correction_add(_b(b, "card"), _b(b, "time"), _b(b, "reader"), _b(b, "note")), "operator"),
    "/api/work/correction/delete": (lambda b: correction_delete(_b(b, "id")), "operator"),
    "/api/work/settings": (lambda b: work_settings_save(_b(b, "settings")), "admin"),
    "/api/me/password": (lambda b: own_password(_b(b, "old"), _b(b, "new")), "viewer"),
    "/api/panel/users/save": (lambda b: panel_user_save(_b(b, "id"), _b(b, "login"), _b(b, "name"), _b(b, "role"),
                                                        _b(b, "pwd"), _b(b, "active") == "1"), "admin"),
    "/api/panel/users/delete": (lambda b: panel_user_delete(_b(b, "id")), "admin"),
    "/api/notify": (lambda b: notify_save(_b(b, "settings")), "admin"),
    "/api/notify/test": (lambda b: notify_test(), "admin"),
    "/api/maintenance": (lambda b: maintenance_save(_b(b, "settings")), "admin"),
    "/api/maintenance/backup": (lambda b: backup_run(manual=True), "admin"),
    "/api/logs/preview": (lambda b: logs_preview(_b(b, "kinds"), _b(b, "ctrl"), _b(b, "before")), "admin"),
    # do dziennika wpisuje samo logs_clear (z liczbą usuniętych wpisów), więc nie ma go w AUDIT_POST
    "/api/logs/clear": (lambda b: logs_clear(_b(b, "kinds"), _b(b, "ctrl"), _b(b, "before")), "admin"),
}


# ścieżki wyłączone w trybie offline (interfejs ich nie pokazuje - to zapora na wypadek starej karty
# przeglądarki albo własnego skryptu klienta): ścieżka -> klucz w OFFLINE_OFF
ONLINE_ONLY = {"/api/live": "live", "/api/doors/open": "doors",
               "/api/notify": "notify", "/api/notify/test": "notify"}


def _door_txt(b):
    return f"drzwi #{_b(b, 'door', '1')}"


def _dept_txt(b):
    with contextlib.suppress(Exception):
        with db() as con:
            r = con.execute("SELECT name FROM departments WHERE id = ?", (_b(b, "id") or _b(b, "dept_id"),)).fetchone()
        return r[0] if r else ""
    return ""


# Dziennik działań: ścieżka -> (opis, szczegóły z zapytania). Bez haseł, kodów i numerów Super Card.
# Odczyty i odpytywanie stanu (autoadd/state, saved/check, swipe/sync, select) nie trafiają do dziennika.
AUDIT_POST = {
    "/api/discover": ("Skan sieci", lambda b: _b(b, "subnet")),
    "/api/connect": ("Połączenie z kontrolerem", lambda b: _b(b, "host")),
    "/api/setip": ("Zmiana adresu IP kontrolera (UDP)", lambda b: f"nr {_b(b, 'device_no')} -> {_b(b, 'ip')}"),
    "/api/disconnect": ("Rozłączenie kontrolera", lambda b: ""),
    "/api/saved/save": ("Zapis kontrolera na liście", lambda b: _b(b, "name")),
    "/api/saved/rename": ("Zmiana nazwy zapisanego kontrolera", lambda b: _b(b, "name")),
    "/api/saved/delete": ("Usunięcie zapisanego kontrolera", lambda b: _b(b, "id")),
    "/api/saved/connect": ("Połączenie z zapisanym kontrolerem", lambda b: _b(b, "id")),
    "/api/saved/autoconnect": ("Automatyczne łączenie", lambda b: ("włączone" if _b(b, "enabled") == "1" else "wyłączone")),
    "/api/departments/add": ("Dodanie działu", lambda b: _b(b, "name")),
    "/api/departments/rename": ("Zmiana nazwy działu", lambda b: _b(b, "name")),
    "/api/departments/delete": ("Usunięcie działu", lambda b: _b(b, "id")),
    "/api/people/assign": ("Przypisanie do działu", lambda b: f"karta {_b(b, 'card')} ({_b(b, 'name')}) → "
                                                              f"{_dept_txt(b) or 'bez działu'}"),
    "/api/tracking": ("Analiza czasu pracy drzwi", lambda b: f"{_door_txt(b)}: " + (
        {"in": "drzwi wejścia", "out": "drzwi wyjścia", "": "nie liczą czasu pracy"}.get(_b(b, "role"), _b(b, "role"))
        if "role" in b else ("włączona" if _b(b, "enabled") == "1" else "wyłączona"))),
    "/api/entryhours": ("Zapis godzin wejścia", lambda b: ""),
    "/api/addcard": ("Dodanie karty", lambda b: f"karta {_b(b, 'card')} ({_b(b, 'name')})"
                                                 + (f", ważna do {_b(b, 'valid_to')}" if _b(b, "valid_to") else "")),
    "/api/cards/bulk": ("Dodanie listy kart", lambda b: f"wierszy: {len([x for x in _b(b, 'list').splitlines() if x.strip()])}"
                                                 + (f", dział: {_dept_txt(b)}" if _b(b, "dept_id") else ", bez działu")
                                                 + (f", ważne do {_b(b, 'valid_to')}" if _b(b, "valid_to") else "")),
    "/api/people/assign-bulk": ("Przypisanie wielu osób do działu",
                                lambda b: f"kart: {len([x for x in re.split(r'[,;\s]+', _b(b, 'cards')) if x])} → "
                                          f"{_dept_txt(b) or 'bez działu'}"),
    "/api/people/forget": ("Usunięcie karty ze spisu panelu", lambda b: f"karta {_b(b, 'card')}"
                                                                         + (f" ({_b(b, 'name')})" if _b(b, "name") else "")),
    "/api/autoadd": ("Tryb dodawania kart przyłożeniem", lambda b: "włączony"),
    "/api/autoadd/stop": ("Tryb dodawania kart przyłożeniem", lambda b: "wyłączony"),
    "/api/edituser": ("Edycja użytkownika", lambda b: f"ID {_b(b, 'user_id')}, karta {_b(b, 'card')}, nazwa „{_b(b, 'name')}”, "
                                                       f"dostęp {_b(b, 'access')}"),
    "/api/deluser": ("Usunięcie użytkownika", lambda b: f"ID {_b(b, 'user_id')}, karta {_b(b, 'card')}"),
    "/api/cards/replace": ("Zmiana numeru karty", lambda b: f"ID {_b(b, 'user_id')}: karta {_b(b, 'old')} → {_b(b, 'new')}"),
    "/api/cards/link": ("Połączenie kart (wymiana w panelu)", lambda b: f"karta {_b(b, 'old')} → {_b(b, 'new')}"),
    "/api/card/validity": ("Ważność karty", lambda b: f"karta {_b(b, 'card')}: {_b(b, 'valid_from') or '…'} – {_b(b, 'valid_to') or '…'}"),
    "/api/card/block": ("Blokada karty", lambda b: f"karta {_b(b, 'card')}" + (f", powód: {_b(b, 'reason')}" if _b(b, "reason") else "")
                                                   + (" (wszystkie połączone kontrolery)" if _b(b, "everywhere") == "1" else "")),
    "/api/card/unblock": ("Odblokowanie karty", lambda b: f"karta {_b(b, 'card')}"),
    "/api/backup/restore": ("Przywracanie użytkowników z kopii", lambda b: f"karty: {_b(b, 'cards')}, działy: {_b(b, 'depts')}"),
    "/api/open": ("Otwarcie drzwi z panelu", _door_txt),
    "/api/doorname": ("Nazwa drzwi", lambda b: f"{_door_txt(b)}: {_b(b, 'name')}"),
    "/api/doordelay": ("Czas otwarcia drzwi", lambda b: f"{_door_txt(b)}: {_b(b, 'sec')} s"),
    "/api/events": ("Rejestr zdarzeń", lambda b: "włączony" if _b(b, "enabled") == "1" else "wyłączony"),
    "/api/doors/open": ("Ostrzeżenie o otwartych drzwiach",
                        lambda b: f"{_door_txt(b)}: " + (f"ostrzeżenie po {_b(b, 'minutes')} min"
                                                          if _b(b, "enabled") == "1" else "bez pilnowania")),
    "/api/language": ("Język kontrolera", lambda b: _b(b, "lang")),
    "/api/supercard": ("Super Card", lambda b: f"slot {_b(b, 'slot')}: {'zapis' if _b(b, 'card') else 'usunięcie'}"),
    "/api/doorpassword": ("Hasło otwarcia drzwi", lambda b: f"{_door_txt(b)}, slot {_b(b, 'slot')}: "
                                                              f"{'zapis' if _b(b, 'pwd') else 'wyczyszczenie'}"),
    "/api/admin": ("Zmiana konta administratora kontrolera", lambda b: f"nowy login „{_b(b, 'new_name')}”"),
    "/api/network": ("Zmiana adresu IP kontrolera", lambda b: f"{_b(b, 'ip')}, brama {_b(b, 'gateway')}"),
    "/api/factoryreset": ("Reset kontrolera do ustawień domyślnych", lambda b: ""),
    "/api/reboot": ("Restart kontrolera", lambda b: ""),
    "/api/synctime": ("Synchronizacja zegara kontrolera", lambda b: ""),
    "/api/work/correction": ("Korekta czasu pracy", lambda b: f"karta {_b(b, 'card')}: "
                                                              f"{'wejście' if _b(b, 'reader') == 'in' else 'wyjście'} {_b(b, 'time')}, "
                                                              f"„{_b(b, 'note')}”"),
    "/api/work/correction/delete": ("Usunięcie korekty czasu pracy", lambda b: f"korekta {_b(b, 'id')}"),
    "/api/work/settings": ("Ustawienia czasu pracy", lambda b: ""),
    "/api/me/password": ("Zmiana własnego hasła panelu", lambda b: ""),
    "/api/panel/users/save": ("Konto panelu", lambda b: f"{'nowe' if not _b(b, 'id') else 'zmiana'}: {_b(b, 'login')}, "
                                                         f"rola {ROLE_NAMES.get(_b(b, 'role'), _b(b, 'role'))}, "
                                                         f"{'aktywne' if _b(b, 'active') == '1' else 'wyłączone'}"
                                                         + (", nowe hasło" if _b(b, "pwd") else "")),
    "/api/panel/users/delete": ("Usunięcie konta panelu", lambda b: f"konto {_b(b, 'id')}"),
    "/api/notify": ("Ustawienia powiadomień", lambda b: ""),
    "/api/notify/test": ("Test powiadomień", lambda b: ""),
    "/api/maintenance": ("Ustawienia zegara i kopii", lambda b: ""),
}
AUDIT_GET = {
    "/api/backup/users.json": ("Pobranie kopii użytkowników", ""),
    "/api/worktime.csv": ("Eksport czasu pracy (CSV)", ""),
    "/print/worktime": ("Wydruk ewidencji czasu pracy", ""),
    "/print/presence": ("Wydruk listy osób w budynku", ""),
    "/api/backups/file": ("Pobranie pliku kopii zapasowej", ""),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ACBPanel"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if TRUST_PROXY and fwd else self.client_address[0]

    def _local(self):
        return (not TRUST_PROXY and not self.headers.get("X-Forwarded-For")
                and self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1"))

    def _secure(self):
        return bool(TLS_CERT) or (TRUST_PROXY and self.headers.get("X-Forwarded-Proto", "") == "https")

    def _token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""

    def _cookie(self, token, max_age):
        return (f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
                + ("; Secure" if self._secure() else ""))

    def _send(self, code, data, ctype, headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200, headers=()):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8", headers)

    def _begin(self):
        _REQ.ip, _REQ.local = self._ip(), self._local()
        _REQ.session = LOCAL_SESSION if AUTH_DISABLED else session_get(self._token())
        return _REQ.session

    def _offline_blocked(self, path):
        """W trybie offline część funkcji nie działa - odpowiadamy wprost, zamiast udawać, że pilnujemy."""
        key = ONLINE_ONLY.get(path) if OFFLINE else None
        if key:
            self._json({"error": f"Niedostępne w trybie offline: {OFFLINE_OFF[key]}. {OFFLINE_WHY}"}, 409)
            return True
        return False

    def _denied(self, sess, role):
        if sess is None:
            self._json({"error": "Zaloguj się do panelu", "login": True}, 401)
            return True
        if ROLES.get(sess["role"], 0) < ROLES[role]:
            self._json({"error": f"Brak uprawnień - wymagana rola: {ROLE_NAMES[role]}"}, 403)
            return True
        return False

    def do_GET(self):
        u = urlparse(self.path)
        sess = self._begin()
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE.replace("{{VERSION}}", APP_VERSION).encode("utf-8"), "text/html; charset=utf-8",
                              [("Content-Security-Policy", "frame-ancestors 'none'")])
        if u.path in ASSETS:
            return self._send(200, ASSETS[u.path], "image/png")
        if u.path == "/api/version":
            return self._json({"app": "acb-panel", "version": APP_VERSION})
        if u.path == "/api/auth":
            return self._json(auth_state())
        q = parse_qs(u.query)
        files = {"/api/worktime.csv": "viewer", "/api/backup/users.json": "operator", "/print/worktime": "viewer",
                 "/print/presence": "viewer", "/api/backups/file": "admin"}
        if u.path in files:
            if self._denied(sess, files[u.path]):
                return
            try:
                if u.path == "/api/worktime.csv":
                    rep, text = worktime_csv(q)
                    ctype, name, data = "text/csv", f"czas-pracy_{rep['from']}_{rep['to']}.csv", text.encode("utf-8")
                elif u.path == "/api/backup/users.json":
                    name, text = users_backup_file()
                    ctype, data = "application/json", text.encode("utf-8")
                elif u.path == "/api/backups/file":
                    name = _b(q, "name")
                    data = backup_file(name)
                    ctype = "application/json" if name.endswith(".json") else "application/octet-stream"
                else:
                    _, page = (print_worktime if u.path == "/print/worktime" else print_presence)(q)
                    audit(AUDIT_GET[u.path][0], u.query[:200])
                    return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            except Exception as e:
                audit(AUDIT_GET[u.path][0], u.query[:200], ok=False, error=str(e))
                if u.path.startswith("/print/"):
                    return self._send(502, _print_page("Błąd", f"<h1>Błąd</h1><p>{html.escape(str(e))}</p>").encode("utf-8"),
                                      "text/html; charset=utf-8")
                return self._json({"error": str(e)}, 502)
            audit(AUDIT_GET[u.path][0], name)
            return self._send(200, data, f"{ctype}; charset=utf-8" if ctype != "application/octet-stream" else ctype,
                              [("Content-Disposition", f'attachment; filename="{name}"')])
        route = ROUTES_GET.get(u.path)
        if not route:
            return self._json({"error": "not found"}, 404)
        if self._denied(sess, route[1]) or self._offline_blocked(u.path):
            return
        try:
            return self._json(route[0](q))
        except Exception as e:
            return self._json({"error": str(e)}, 502)

    def do_POST(self):
        u = urlparse(self.path)
        ln = int(self.headers.get("Content-Length", 0) or 0)
        if ln > 5 * 1024 * 1024:
            return self._json({"error": "Za duże zapytanie"}, 413)
        raw = self.rfile.read(ln) if ln else b""
        # ochrona przed wysłaniem formularza z obcej strony (CSRF): własny nagłówek + zgodny Origin
        origin = self.headers.get("Origin", "")
        if self.headers.get("X-ACB") != "1" or (origin and urlparse(origin).netloc != self.headers.get("Host", "")):
            return self._json({"error": "Odrzucono zapytanie spoza panelu"}, 403)
        body = parse_qs(raw.decode("utf-8")) if raw else {}
        sess = self._begin()
        agent = self.headers.get("User-Agent", "")
        try:
            if u.path == "/api/login":
                token = login(_b(body, "login"), _b(body, "pwd"), _REQ.ip, agent)
                _REQ.session = session_get(token)
                return self._json(dict(auth_state(), ok=True), headers=[("Set-Cookie", self._cookie(token, SESSION_MAX))])
            if u.path == "/api/setup":
                token = setup_admin(body, _REQ.ip, agent, _REQ.local)
                _REQ.session = session_get(token)
                return self._json(dict(auth_state(), ok=True), headers=[("Set-Cookie", self._cookie(token, SESSION_MAX))])
            if u.path == "/api/logout":
                if sess and sess.get("token") != "local":
                    audit("Wylogowanie")
                    session_drop(sess["token"])
                return self._json({"ok": True}, headers=[("Set-Cookie", self._cookie("", 0))])
        except AuthError as e:
            return self._json({"error": str(e)}, e.code)
        except Exception as e:
            return self._json({"error": str(e)}, 400)
        route = ROUTES_POST.get(u.path)
        if not route:
            return self._json({"error": "not found"}, 404)
        if self._denied(sess, route[1]) or self._offline_blocked(u.path):
            return
        desc = AUDIT_POST.get(u.path)
        details = ""
        if desc:
            with contextlib.suppress(Exception):
                details = desc[1](body)
        try:
            result = route[0](body)
        except Exception as e:
            if desc:
                audit(desc[0], details, ok=False, error=str(e))
            return self._json({"error": str(e)}, 502)
        if desc:
            audit(desc[0], details)
        return self._json(result)


# Logo Spreest w interfejsie. Panel jest jednym plikiem .py (klient nie dostaje katalogu z grafikami),
# więc obrazki siedzą w kodzie i panel serwuje je z pamięci pod /logo.png i /favicon.png.
# Napis w LOGO_PNG jest biały, bo interfejs ma ciemny motyw; ICON_PNG to sam znak (domek) na ciemnym
# kaflu - czytelny i na jasnym, i na ciemnym pasku zakładek przeglądarki.
LOGO_PNG = base64.b64decode(
    "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")
ICON_PNG = base64.b64decode(
    "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"
    "D8VWb+m37lmjAAAAAElFTkSuQmCC")
ICON_BIG_PNG = base64.b64decode(
    "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"
    "YII=")
ASSETS = {"/logo.png": LOGO_PNG, "/favicon.png": ICON_PNG, "/favicon.ico": ICON_PNG, "/icon-180.png": ICON_BIG_PNG}


PAGE = r"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spreest - Panel ACB</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="apple-touch-icon" href="/icon-180.png">
<style>
:root{--bg:#0c111a;--side:#111724;--card:#171e2b;--line:#273042;--line2:#1f2736;--fg:#e6ecf5;--mut:#8a97ad;--in:#0d131f;--hover:#1f2838;
--acc:#3b82f6;--acc-soft:#18294a;--link:#93c5fd;
--ok:#22c55e;--ok-t:#4ade80;--ok-soft:#0f2418;--ok-line:#1f6f3f;
--warn:#f59e0b;--warn-t:#fbbf24;--warn-soft:#211a0b;--warn-line:#5a4620;
--err:#ef4444;--err-t:#f87171;--err-soft:#2a1212;--err-line:#6f1f1f;
--hh:62px;--sw:236px}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{color-scheme:dark}
body{margin:0;font:14px/1.5 system-ui,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg)}
a{color:var(--link)}
h1{font-size:22px;margin:0;line-height:1.25}
h2{font-size:16px;margin:0;line-height:1.3}
h3{font-size:11px;margin:0 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.07em;font-weight:600}
input,button,select{font:inherit}
input[type=text],input[type=password],input[type=number],input[type=date],input[type=time],select{background:var(--in);border:1px solid var(--line);color:var(--fg);padding:8px 10px;border-radius:8px;outline:none;max-width:100%}
input:focus,select:focus{border-color:var(--acc)}
input:disabled{opacity:.45}
input[type=checkbox]{accent-color:var(--acc)}

/* --- górny pasek: połączenie --- */
header{position:sticky;top:0;z-index:6;display:flex;align-items:center;gap:16px;padding:9px 20px;background:var(--side);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;width:auto;min-width:calc(var(--sw) - 36px);flex:none;font-weight:700;font-size:15px;white-space:nowrap}
.brand .logo{height:30px;width:auto;flex:none}
.brand .logo+div{border-left:1px solid var(--line);padding-left:12px}
.brand .ver{display:block;font-size:11px;font-weight:400;color:var(--mut)}
.conn{display:flex;align-items:center;gap:14px;flex:1;min-width:0;padding:7px 10px 7px 14px;border-radius:10px;border:1px solid var(--line);background:var(--in);box-shadow:inset 4px 0 0 var(--mut)}
.conn.on{border-color:var(--ok-line);background:var(--ok-soft);box-shadow:inset 4px 0 0 var(--ok)}
.conn.err{border-color:var(--err-line);background:var(--err-soft);box-shadow:inset 4px 0 0 var(--err)}
.conn .cinfo{min-width:0;flex:1}
.conn .ck{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mut)}
.conn.on .ck{color:var(--ok-t)}.conn.err .ck{color:var(--err-t)}
.conn .cline{display:flex;align-items:baseline;gap:4px 12px;flex-wrap:wrap}
.conn .cname{font-size:16px;font-weight:700;word-break:break-word}
.conn .cmeta{font-size:12px;color:var(--mut)}.conn .cmeta b{color:var(--fg);font-family:ui-monospace,Consolas,monospace;font-weight:600}
.conn .cclock{text-align:right;line-height:1.2;padding-left:14px;border-left:1px solid var(--line)}
.conn .cclock .t{font:700 17px ui-monospace,Consolas,monospace}
.conn .cact{display:flex;gap:6px;flex:none}
.dot{width:10px;height:10px;border-radius:50%;background:var(--mut);flex:none}
.dot.on{background:var(--ok)}.dot.off{background:var(--err)}
.conn .dot{width:12px;height:12px}.conn.on .dot{box-shadow:0 0 0 4px #14532d}

/* --- układ: menu boczne + treść --- */
.shell{display:flex;align-items:flex-start}
nav{position:sticky;top:var(--hh);width:var(--sw);flex:none;height:calc(100vh - var(--hh));overflow-y:auto;padding:14px 10px;background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;gap:2px}
nav button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:none;color:var(--mut);padding:8px 12px;border-radius:8px;cursor:pointer;font-size:14px}
nav button .i{width:22px;text-align:center;font-size:15px;flex:none}
nav button.active{background:var(--acc-soft);color:#fff;box-shadow:inset 3px 0 0 var(--acc)}
nav button:hover:not(.active){background:var(--hover);color:var(--fg)}
nav .navctl{display:flex;align-items:center;gap:8px;margin:12px 2px 4px;padding:12px 10px 0;border-top:1px solid var(--line);font-size:13px;font-weight:700;color:var(--fg);min-width:0}
nav .navctl .dot{width:8px;height:8px}
nav .navctl #navCtlName{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
nav .navsec{margin:12px 12px 3px;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mut)}
main{flex:1;min-width:0;padding:22px 28px 60px;max-width:1200px}

/* --- strona, karty, formularze --- */
.tab{display:none}.tab.active{display:block}
.ph{display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap;margin:0 0 18px}
.ph>div{flex:1;min-width:240px}
.ph p{margin:4px 0 0;color:var(--mut);max-width:780px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.card.danger{border-color:var(--err-line)}.card.danger h2{color:var(--err-t)}
.ch{display:flex;align-items:center;gap:8px 10px;flex-wrap:wrap;margin:0 0 12px}
.lead{margin:-4px 0 14px;color:var(--mut);font-size:13px}
.cols2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(360px,100%),1fr));gap:16px;margin-bottom:16px}
.cols2>.card{margin-bottom:0}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.spacer{flex:1}
label.fld{display:block;margin:0 0 10px}label.fld .lbl{display:block;color:var(--mut);font-size:12px;margin-bottom:4px}
.form{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:12px;align-items:end;margin-bottom:12px}
.form label.fld{margin:0}.form input,.form select{width:100%}
.toolbar{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;padding:12px;margin:0 0 14px;background:var(--in);border:1px solid var(--line2);border-radius:10px}
.toolbar label.fld{margin:0}
.muted{color:var(--mut)}.small{font-size:12px}
.wgc{border-bottom:1px dotted currentColor;cursor:help}
.warn-t{color:var(--warn-t)}.ok-t{color:var(--ok-t)}.err-t{color:var(--err-t)}
.hint{margin:8px 0 0;font-size:12px;color:var(--mut)}

/* komunikaty i rozwijana pomoc */
.note{padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:var(--in);font-size:13px;margin:0 0 14px}
.note.warn{border-color:var(--warn-line);background:var(--warn-soft)}
.note.err{border-color:var(--err-line);background:var(--err-soft)}
.note.ok{border-color:var(--ok-line);background:var(--ok-soft)}
details.note>summary{cursor:pointer}
details.note[open]>summary{margin-bottom:6px}
details.help{margin-top:12px;font-size:13px}
details.help>summary{cursor:pointer;color:var(--link);display:inline-block;list-style:none}
details.help>summary::-webkit-details-marker{display:none}
details.help>summary::before{content:"▸ ";color:var(--mut)}
details.help[open]>summary::before{content:"▾ "}
details.help .hb{margin-top:8px;padding:2px 0 2px 14px;border-left:2px solid var(--line);color:var(--mut)}
details.help .hb b{color:var(--fg)}
details.help ul{margin:0;padding-left:18px}details.help li+li{margin-top:5px}
details.help p{margin:0 0 6px}

/* przyciski */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;background:var(--acc);color:#fff;border:1px solid transparent;padding:8px 14px;border-radius:8px;cursor:pointer;white-space:nowrap}
.btn:hover{filter:brightness(1.1)}.btn:disabled{opacity:.5;cursor:not-allowed;filter:none}
.btn.ghost{background:var(--hover);border-color:var(--line);color:var(--fg)}
.btn.danger{background:#dc2626}.btn.ok{background:#16a34a}
.btn.sm{padding:5px 10px;font-size:13px}
.btn.big{padding:11px 18px;font-size:15px;font-weight:600}
.iconbtn{background:transparent;border:1px solid var(--line);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px;color:var(--fg);white-space:nowrap}
.iconbtn:hover{background:var(--hover)}.iconbtn.del{color:var(--err-t)}.iconbtn.del:hover{background:var(--err);color:#fff}

/* tabele */
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line2);font-size:13px;vertical-align:middle}
th{color:var(--mut);font-weight:600;font-size:12px;border-bottom-color:var(--line);white-space:nowrap}
td.act{text-align:right;white-space:nowrap}
tr.cur td{background:var(--ok-soft)}
tr.grant td:first-child{box-shadow:inset 3px 0 0 var(--ok)}
tr.deny td:first-child{box-shadow:inset 3px 0 0 var(--warn)}
tr.grp td{background:var(--in);color:var(--link);font-weight:600;padding-top:12px}
td.dir{white-space:nowrap}.e{font-size:16px;vertical-align:-2px}
tr.wt{cursor:pointer}tr.wt:hover td{background:var(--hover)}
tr.wtd>td{background:var(--in);padding:4px 10px 12px 28px}
tr.wtd table td,tr.wtd table th{font-size:12px;padding:5px 8px}
.pager{display:flex;gap:6px;align-items:center;margin-top:12px;flex-wrap:wrap}

/* drobne elementy */
.pill{display:inline-block;padding:1px 9px;border-radius:20px;font-size:12px;white-space:nowrap}
.pill.on{background:#14331f;color:var(--ok-t)}.pill.off{background:#3a1c1c;color:var(--err-t)}
.pill.mdl{background:#1e2a44;color:var(--link)}.pill.unv{background:#3a3320;color:var(--warn-t)}
.chip{display:inline-flex;align-items:center;gap:8px;background:var(--in);border:1px solid var(--line);border-radius:10px;padding:5px 7px 5px 12px}
.chip .iconbtn{padding:2px 8px}
.kv{background:var(--in);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kv .k{color:var(--mut);font-size:12px}.kv .v{font-size:17px;font-weight:600;margin-top:2px;word-break:break-word}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--mut);border-top-color:var(--acc);border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--in);border:1px solid var(--line);padding:12px 20px;border-radius:10px;opacity:0;transition:.3s;pointer-events:none;max-width:90%;z-index:9;box-shadow:0 8px 30px #0008}
#toast.show{opacity:1}#toast.err{border-color:var(--err)}#toast.ok{border-color:var(--ok)}
dialog{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:12px;padding:20px;width:min(440px,92vw)}
dialog::backdrop{background:#0009}
dialog h2{margin-bottom:14px}

/* pulpit */
.doorgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(230px,100%),1fr));gap:12px}
.doortile{background:var(--in);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.doortile .dn{font-size:12px;color:var(--mut)}
.doortile .dname{font-size:16px;font-weight:600;word-break:break-word}
.doortile .btn{margin-top:12px}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(270px,100%),1fr));gap:12px}
.sgrp{background:var(--in);border:1px solid var(--line2);border-radius:10px;padding:12px 14px}
.kvl{display:grid;grid-template-columns:auto 1fr;gap:7px 14px;margin:0;font-size:13px}
.kvl dt{color:var(--mut)}.kvl dd{margin:0;font-weight:600;text-align:right;word-break:break-word}
.clockbig{font:700 26px ui-monospace,Consolas,monospace;margin:2px 0 4px}

/* logowanie */
body.locked header,body.locked .shell{display:none}
.authview{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.authbox{width:min(400px,100%);background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 24px}
.authbox .brand{width:auto;min-width:0;margin-bottom:18px}
.authbox .brand .logo{height:38px}
.authbox h1{margin-bottom:6px}.authbox label.fld input{width:100%}
.authbox .btn{width:100%;margin-top:6px}
/* użytkownik panelu w nagłówku */
.who{display:flex;align-items:center;gap:8px;flex:none}
.who .wn{line-height:1.2;text-align:right;font-size:13px}.who .wn span{display:block;font-size:11px;color:var(--mut)}
#ctrlSwitch{padding:5px 8px;max-width:220px}
/* na żywo i obecni */
.live{display:flex;flex-direction:column;gap:2px;max-height:420px;overflow-y:auto}
.live .ev{display:grid;grid-template-columns:62px 26px 1fr auto;gap:8px;align-items:baseline;padding:6px 8px;border-radius:8px;font-size:13px}
.live .ev:nth-child(odd){background:var(--in)}
.live .ev.alert{background:var(--warn-soft);box-shadow:inset 3px 0 0 var(--warn)}
.live .ev.alarm{background:var(--err-soft);box-shadow:inset 3px 0 0 var(--err)}
.live .ev.fresh{animation:fresh 2s ease-out}
@keyframes fresh{from{background:var(--acc-soft)}}
.live .t{font-family:ui-monospace,Consolas,monospace;color:var(--mut);font-size:12px}
.pres{display:flex;flex-wrap:wrap;gap:6px}
.pres .chip{padding:4px 10px}
.pill.warn{background:#3a3320;color:var(--warn-t)}
tr.past td{opacity:.55}
.corr{color:var(--link);cursor:help}
.kvgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr));gap:10px 14px}

@media (max-width:900px){
  header{position:static;flex-wrap:wrap;padding:10px 16px}
  .brand{width:auto;min-width:0}
  .conn{flex-basis:100%;flex-wrap:wrap}
  .conn .cclock{border-left:none;padding-left:0;text-align:left}
  .shell{display:block}
  nav{position:sticky;top:0;z-index:5;width:auto;height:auto;flex-direction:row;overflow-x:auto;padding:8px 12px;border-right:none;border-bottom:1px solid var(--line)}
  nav button{width:auto;white-space:nowrap;padding:7px 11px}
  nav .navctl,nav .navsec{display:none!important}
  main{padding:16px 16px 60px}
  .who{flex-basis:100%;justify-content:flex-end}
}
</style></head><body class="locked">
<div id="authView" class="authview">
  <div class="authbox">
    <div class="brand"><img class="logo" src="/logo.png" width="190" height="64" alt="Spreest"><div>Panel ACB<span class="ver">kontrola dostępu · v{{VERSION}}</span></div></div>
    <form id="loginForm" onsubmit="doLogin(event)" hidden>
      <h1>Zaloguj się</h1><p class="muted small" style="margin:0 0 14px">Konto panelu nadaje administrator panelu.</p>
      <label class="fld"><span class="lbl">Login</span><input type="text" id="lgLogin" autocomplete="username" required></label>
      <label class="fld"><span class="lbl">Hasło</span><input type="password" id="lgPwd" autocomplete="current-password" required></label>
      <button class="btn big" id="lgBtn">Zaloguj</button>
      <p class="small err-t" id="lgErr" style="margin:10px 0 0"></p>
    </form>
    <form id="setupForm" onsubmit="doSetup(event)" hidden>
      <h1>Pierwsze uruchomienie</h1>
      <p class="muted small" style="margin:0 0 14px">Utwórz konto administratora panelu. Kolejne konta (także z mniejszymi uprawnieniami) dodasz potem w zakładce „Konta panelu”.</p>
      <label class="fld"><span class="lbl">Login</span><input type="text" id="suLogin" autocomplete="username" required maxlength="40"></label>
      <label class="fld"><span class="lbl">Imię i nazwisko</span><input type="text" id="suName" maxlength="60"></label>
      <label class="fld"><span class="lbl">Hasło (co najmniej 8 znaków)</span><input type="password" id="suPwd" autocomplete="new-password" required minlength="8"></label>
      <label class="fld"><span class="lbl">Powtórz hasło</span><input type="password" id="suPwd2" autocomplete="new-password" required minlength="8"></label>
      <div id="suCodeRow">
        <div class="note" style="margin:4px 0 10px">
          <b>Potrzebny jest 8-cyfrowy kod.</b> Chroni przed tym, żeby konto administratora założył ktoś przypadkowy z sieci -
          kod zobaczy tylko osoba z dostępem do komputera, na którym działa panel.
          <div id="suCodeHelp" class="small" style="margin-top:8px"></div>
        </div>
        <label class="fld"><span class="lbl">Kod</span><input type="text" id="suCode" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="8 cyfr"></label>
      </div>
      <button class="btn big" id="suBtn">Utwórz konto i zaloguj</button>
      <p class="small err-t" id="suErr" style="margin:10px 0 0"></p>
    </form>
  </div>
</div>
<header>
  <div class="brand"><img class="logo" src="/logo.png" width="190" height="64" alt="Spreest"><div>Panel ACB<span class="ver">kontrola dostępu · v{{VERSION}}<span class="pill unv" id="modeBadge" hidden title="Panel uruchamiany doraźnie - funkcje wymagające stałego połączenia są wyłączone" style="margin-left:6px">tryb offline</span></span></div></div>
  <div class="conn" id="conn">
    <span class="dot" id="dot"></span>
    <div class="cinfo">
      <div class="ck" id="connK">Brak połączenia</div>
      <div class="cline"><span class="cname" id="connName">Nie wybrano kontrolera</span>
        <span class="cmeta" id="connMeta">Wybierz zapisany kontroler albo wyszukaj go w sieci.</span></div>
    </div>
    <div class="cclock" id="connClock" hidden title="Czas kontrolera: odczytany raz przy połączeniu (i po synchronizacji), dalej liczony w przeglądarce">
      <div class="ck">🕒 Czas kontrolera</div><div class="t devclock">—</div><div class="small" id="connClockInfo"></div>
    </div>
    <div class="cact">
      <select id="ctrlSwitch" onchange="switchCtrl(this.value)" hidden title="Połączone kontrolery - wybierz, który oglądasz"></select>
      <span data-role="admin"><button class="btn ghost sm" id="saveActiveBtn" onclick="saveActive()" hidden>Zapisz kontroler</button></span>
      <span data-role="admin"><button class="btn ghost sm" id="disconnectBtn" onclick="disconnectActive()" hidden>Rozłącz</button></span>
    </div>
  </div>
  <div class="who">
    <div class="wn"><b id="whoName"></b><span id="whoRole"></span></div>
    <button class="btn ghost sm" id="whoPwd" onclick="changeOwnPwd()" title="Zmień swoje hasło do panelu">🔑</button>
    <button class="btn ghost sm" id="whoOut" onclick="logout()">Wyloguj</button>
  </div>
</header>
<div class="shell">
<nav>
  <button data-tab="find" class="active"><span class="i">🖧</span>Kontrolery</button>
  <div class="navctl" data-need hidden title="Zakładki poniżej dotyczą tego kontrolera"><span class="dot on"></span><span id="navCtlName"></span></div>
  <button data-tab="dash" data-need hidden><span class="i">🏠</span>Pulpit</button>
  <div class="navsec" data-need hidden>Ludzie i ruch</div>
  <button data-tab="cards" data-need hidden><span class="i">👥</span>Pracownicy i karty</button>
  <button data-tab="log" data-need hidden><span class="i">📋</span>Log przejść</button>
  <button data-tab="work" data-need hidden><span class="i">⏱️</span>Czas pracy</button>
  <div class="navsec" data-need hidden>Konfiguracja</div>
  <button data-tab="door" data-need hidden><span class="i">🚪</span>Drzwi</button>
  <button data-tab="hours" data-need hidden><span class="i">🕒</span>Godziny wejścia</button>
  <button data-tab="codes" data-need data-role="admin" hidden><span class="i">🔑</span>Hasła i Super Card</button>
  <button data-tab="system" data-need data-role="admin" hidden><span class="i">⚙️</span>System</button>
  <div class="navsec" data-role="admin" hidden>Panel</div>
  <button data-tab="notify" data-role="admin" data-online hidden><span class="i">🔔</span>Powiadomienia</button>
  <button data-tab="audit" data-role="admin" hidden><span class="i">🧾</span>Dziennik działań</button>
  <button data-tab="accounts" data-role="admin" hidden><span class="i">👤</span>Konta panelu</button>
  <button data-tab="settings" data-role="admin" hidden><span class="i">🛠️</span>Ustawienia panelu</button>
</nav>
<main>
  <div class="note warn" id="credWarn" hidden>
    <div class="row">
      <div style="flex:1;min-width:220px"><b class="warn-t">⚠️ Urządzenie korzysta z domyślnych danych logowania.</b><br>
        <span class="small muted">Każdy w sieci może się zalogować, znając fabryczny login i hasło. Zalecamy zmianę danych logowania w zakładce „System”.</span></div>
      <button class="btn sm" onclick="goTab('system')">Zmień dane logowania</button>
    </div>
  </div>
  <details class="note" id="httpWarn" hidden>
    <summary><span class="warn-t">🔓 Połączenie z kontrolerem nie jest szyfrowane (HTTP)</span> <span class="muted small">- co to oznacza?</span></summary>
    <span class="small muted">Kontroler obsługuje wyłącznie HTTP (i nieszyfrowany kanał UDP 60000): login, hasło, numery kart i polecenia
      (także otwarcie drzwi) idą między panelem a kontrolerem otwartym tekstem i każdy, kto ma dostęp do tej sieci, może je podsłuchać.
      Nie da się tego zmienić w kontrolerze. Połączenie przeglądarki z panelem można zaszyfrować (HTTPS - zob. „Ustawienia panelu”).
      Trzymaj kontroler w wydzielonej sieci / VLAN, do której ma dostęp tylko komputer z panelem, z dala od Wi-Fi dla gości
      i nigdy wystawiony do internetu.</span>
  </details>

  <div class="note" id="offlineNote" data-offline hidden>
    <b>🔌 Panel działa w trybie offline</b> - do pracy doraźnej, np. po wyciąg czasu pracy.
    Po uruchomieniu łączy się z zapisanym kontrolerem, pobiera log przejść i trzyma połączenie do zamknięcia programu.
    <span class="small muted">Wyłączone są funkcje, które wymagają panelu włączonego bez przerwy:</span>
    <ul class="small muted" id="offlineOffList" style="margin:6px 0 0;padding-left:20px"></ul>
    <span class="small muted">Potrzebujesz ich stale? Uruchom panel w wersji online na komputerze włączonym cały czas.</span>
    <div class="small" id="offlineWait" hidden style="margin-top:8px"><span class="spin"></span> Łączenie z zapisanym kontrolerem...</div>
  </div>

  <!-- KONTROLERY -->
  <section id="find" class="tab active">
    <div class="ph"><div><h1>Kontrolery</h1>
      <p data-online>Panel może być połączony z kilkoma kontrolerami naraz - godziny wejścia, zdarzenia na żywo, powiadomienia i kopie działają dla wszystkich połączonych. Zakładki poniżej dotyczą kontrolera wybranego w górnym pasku.</p>
      <p data-offline hidden>Panel może być połączony z kilkoma kontrolerami naraz. Zakładki poniżej dotyczą kontrolera wybranego w górnym pasku. W trybie offline panel łączy się sam po uruchomieniu z każdym zapisanym kontrolerem, który ma zapamiętane hasło.</p></div></div>
    <div class="card" id="connCard" hidden>
      <div class="ch"><h2>Połączone teraz</h2><span class="muted small" id="connCount"></span></div>
      <div class="tw"><table><thead><tr><th>Nazwa</th><th>Adres IP</th><th>Model</th><th></th></tr></thead><tbody id="connBody"></tbody></table></div>
    </div>
    <div class="card">
      <div class="ch"><h2>Zapisane kontrolery</h2><span class="muted small" id="savedCount"></span><div class="spacer"></div>
        <button class="btn ghost sm" id="checkBtn" onclick="checkOnline(this)">Sprawdź stan</button></div>
      <div class="tw"><table><thead><tr>
        <th>Stan</th><th>Nazwa</th><th>Adres IP</th><th>Model</th><th>Login</th><th title="Panel łączy się sam po uruchomieniu (wymaga zapamiętanego hasła)">Łącz sam</th><th></th>
      </tr></thead><tbody id="savedBody">
        <tr><td colspan="7" class="muted">—</td></tr>
      </tbody></table></div>
      <p class="hint">Aby zapisać kontroler, połącz się z nim i kliknij „Zapisz kontroler” w górnym pasku.</p>
      <details class="help"><summary>Skąd panel wie, czy kontroler jest online</summary>
        <div class="hb">Stan online panel sprawdza sam co <span id="onlinePoll">30</span> s, bez logowania i bez zajmowania połączenia z kontrolerem (port UDP 60000). Jeśli firewall blokuje ten port, kontroler będzie widoczny jako offline, mimo że połączenie może działać.</div></details>
      <details class="help"><summary>Automatyczne łączenie - kiedy je włączyć</summary>
        <div class="hb"><p>Zaznacz „Łącz sam” przy kontrolerach, które panel ma obsługiwać bez udziału człowieka - np. gdy godziny wejścia mają <b>kilka zmian</b> (PIN-y przełącza panel), gdy mają działać powiadomienia albo automatyczne kopie. Po uruchomieniu panel odczeka ok. minuty (kontroler zwalnia poprzednie połączenie z opóźnieniem) i połączy się sam, tylko zapamiętanym hasłem.</p>
          <p>Kontroler rozłączony ręcznie nie łączy się sam aż do ponownego ręcznego połączenia albo restartu panelu. Nieudane próby są ponawiane coraz rzadziej (co 1,5 min, 4,5 min... do 1 h), bo każde nowe połączenie zużywa jedno z ograniczonych miejsc na połączenia w kontrolerze.</p></div></details>
    </div>
    <div class="cols2" data-role="admin">
      <div class="card">
        <h2>Wyszukaj w sieci lokalnej</h2>
        <p class="hint" style="margin:4px 0 12px">Model rozpoznawany po liczbie drzwi: ACB-001 = 1, ACB-002 = 2, ACB-004 = 4.
          Skan znajduje też kontrolery z adresem spoza tej sieci (np. po resecie) - nadasz im adres przyciskiem „Ustaw adres IP”.</p>
        <div class="form">
          <label class="fld"><span class="lbl">Podsieć</span><input type="text" id="subnet" placeholder="192.168.1.0/24"></label>
          <label class="fld"><span class="lbl">Login</span><input type="text" id="scanUser"></label>
          <label class="fld"><span class="lbl">Hasło</span><input type="password" id="scanPwd"></label>
        </div>
        <div class="row"><button class="btn" id="scanBtn" onclick="scan()">🔍 Skanuj</button>
          <span class="muted small" id="scanInfo"></span></div>
      </div>
      <div class="card">
        <h2>Połącz po adresie IP</h2>
        <p class="hint" style="margin:4px 0 12px">Gdy znasz adres kontrolera albo skan go nie znajduje.</p>
        <div class="form">
          <label class="fld"><span class="lbl">Adres IP</span><input type="text" id="directIp" placeholder="192.168.1.100"></label>
          <label class="fld"><span class="lbl">Login</span><input type="text" id="directUser" placeholder="login"></label>
          <label class="fld"><span class="lbl">Hasło</span><input type="password" id="directPwd" placeholder="hasło"
            onkeydown="if(event.key==='Enter')$('#directBtn').click()"></label>
        </div>
        <button class="btn ok" id="directBtn" onclick="connectTo($('#directIp').value.trim(),$('#directUser').value,$('#directPwd').value)">Połącz</button>
      </div>
    </div>
    <div class="card" id="foundCard" hidden>
      <div class="ch"><h2>Znalezione w sieci</h2><span class="muted small" id="foundCount"></span></div>
      <div class="tw"><table><thead><tr>
        <th>Adres IP</th><th>Model</th><th>Nr urządzenia</th><th>Wersja</th><th></th>
      </tr></thead><tbody id="foundBody">
        <tr><td colspan="5" class="muted">Uruchom skan, aby wyszukać kontrolery w sieci.</td></tr>
      </tbody></table></div>
    </div>
  </section>

  <!-- PULPIT -->
  <section id="dash" class="tab">
    <div class="ph"><div><h1>Pulpit</h1><p>Ruch przy drzwiach na żywo, osoby w środku, szybkie otwarcie drzwi i stan kontrolera.</p></div></div>
    <div class="note warn" id="doorOpenNote" data-online hidden></div>
    <div class="card" data-role="operator">
      <div class="ch"><h2>Otwórz drzwi</h2></div>
      <div class="doorgrid" id="doorButtons"></div>
    </div>
    <div class="cols2">
      <div class="card" data-online>
        <div class="ch"><h2>Na żywo</h2><span class="small muted" id="liveState"></span><div class="spacer"></div>
          <label class="small muted" style="white-space:nowrap" title="Powiadomienia systemowe przeglądarki o odmowach i alarmach, gdy panel jest otwarty w tle"><input type="checkbox" id="liveNotif" onchange="toggleBrowserNotif(this)"> w przeglądarce</label></div>
        <div class="live" id="liveList"><div class="muted small">Czekam na zdarzenia...</div></div>
        <p class="hint">Zdarzenia z kontrolera odczytywane co sekundę (UDP 60000). Odmowy i alarmy z <b>innych</b> połączonych kontrolerów pokazują się jako komunikat.</p>
      </div>
      <div class="card">
        <div class="ch"><h2>Teraz w środku</h2><span class="pill on" id="presCount" hidden></span><div class="spacer"></div>
          <button class="btn ghost sm" onclick="window.open('/print/presence','_blank')">🖨️ Lista ewakuacyjna</button></div>
        <div id="presList" class="muted small">—</div>
        <p class="hint" id="presInfo"></p>
        <p class="hint" data-offline hidden>W trybie offline lista wynika z <b>pobranego logu przejść</b> - jest aktualna na chwilę
          ostatniego pobrania (panel dociąga log sam przy otwarciu tej zakładki, jeśli minęło ponad 5 minut).</p>
      </div>
    </div>
    <div class="card">
      <div class="ch"><h2>Stan urządzenia</h2><div class="spacer"></div>
        <button class="btn ghost sm" onclick="loadStatus()">Odśwież</button></div>
      <div class="sgrid" id="statusGrid"><div class="muted">—</div></div>
    </div>
  </section>

  <!-- PRACOWNICY I KARTY -->
  <section id="cards" class="tab">
    <div class="ph"><div><h1>Pracownicy i karty</h1>
      <p>Karty zapisane w kontrolerze, ich nazwy, działy i dostęp do drzwi.</p></div></div>
    <div class="cols2">
      <div class="card" data-role="operator">
        <h2>Dodaj kartę</h2>
        <div class="form" style="margin-top:12px">
          <label class="fld"><span class="lbl">Numer karty</span>
            <input type="text" id="newCard" placeholder="same cyfry" inputmode="numeric" oninput="cardHint()"></label>
          <label class="fld"><span class="lbl">Nazwa / właściciel</span>
            <input type="text" id="newName" placeholder="np. Jan Kowalski" onkeydown="if(event.key==='Enter')addCard()"></label>
          <label class="fld" title="Karta sama przestanie działać po tym dniu - np. gość, praktykant, firma zewnętrzna"><span class="lbl">Ważna do (opcjonalnie)</span>
            <input type="date" id="newValidTo"></label>
        </div>
        <div class="row">
          <button class="btn" onclick="addCard()">Dodaj ręcznie</button>
          <span class="muted small">albo</span>
          <button class="btn ghost" id="autoBtn" onclick="autoAdd()">Przyłóż kartę do czytnika</button>
          <button class="btn danger" id="autoStopBtn" onclick="autoStop()" hidden>Zakończ dodawanie</button>
        </div>
        <p class="small warn-t" id="cardHint" style="margin:8px 0 0" hidden></p>
        <p class="small" id="autoInfo" style="margin:8px 0 0"></p>
        <p class="hint">Numer karty wpisuj <b>bez zer poprzedzających</b>. Jeśli identyfikator karty ma np. 6 cyfr, a na karcie jest nadrukowane <b>0000123456</b>, wpisz tylko <b>123456</b>. Numer <b>powyżej 65535</b> kontroler widzi inaczej niż jest nadrukowany na karcie - przelicz go niżej.</p>
        <details class="help"><summary>Numer na karcie a numer w kontrolerze (karty 13,56 MHz)</summary>
          <div class="hb">
            <p>Czytnik nie przekazuje kontrolerowi numeru karty wprost. Wysyła <b>24 bity</b> (Wiegand-26) rozbite na
              <b>kod obiektu</b> (8 bitów, 0-255) i <b>numer karty</b> (16 bitów, 0-65535), a kontroler skleja je z powrotem
              <b>dziesiętnie</b>, tak jakby druga część miała zawsze 5 cyfr:</p>
            <p><b>numer w kontrolerze = kod obiektu × 100000 + numer karty</b>, gdzie
              kod obiektu = numer z karty ÷ 65536, numer karty = reszta z tego dzielenia.</p>
            <ul>
              <li>Numery <b>do 65535</b> są po obu stronach takie same - tu nie ma się czym przejmować.</li>
              <li>Powyżej 65535 numery <b>przeskakują</b>: 65535 → 65535, ale 65536 → 100000, 99999 → 134463, 999999 → 1516959.</li>
              <li>Numery, w których <b>pięć ostatnich cyfr przekracza 65535</b> (np. 170000), nie pojawią się nigdy - żadna karta ich nie zgłosi.</li>
              <li>Numer będący wielokrotnością <b>16777216</b> czytnik widzi jako <b>0</b> - takiej karty kontroler nie zapisuje nawet w logu.</li>
              <li>Najpewniejszy sposób na numer bez liczenia: <b>„Przyłóż kartę do czytnika”</b> - kontroler zapisze kartę pod numerem, który sam widzi.</li>
            </ul>
            <div class="row" style="align-items:flex-end;margin:10px 0 6px">
              <label class="fld"><span class="lbl">Numer nadrukowany na karcie</span>
                <input type="text" id="wgCard" inputmode="numeric" placeholder="np. 99999" oninput="wgCalc('card')" style="width:170px"></label>
              <span class="muted" style="padding-bottom:9px">⇄</span>
              <label class="fld"><span class="lbl">Numer w kontrolerze (ten wpisuj w panelu)</span>
                <input type="text" id="wgCtrl" inputmode="numeric" placeholder="np. 134463" oninput="wgCalc('ctrl')" style="width:170px"></label>
            </div>
            <p id="wgMsg" class="small"></p>
            <p>Sprawdzone na sprzęcie (ACB-002, 2026-09-18): 10000 → 10000, 12345 → 12345, 99999 → 134463,
              100000 → 134464, 999999 → 1516959, 16777216 → karta niewidoczna dla kontrolera.</p>
          </div></details>
      </div>
      <div class="card">
        <h2>Działy</h2>
        <div class="row" style="margin-top:12px;flex-wrap:nowrap" data-role="operator">
          <input type="text" id="newDept" maxlength="40" placeholder="Nazwa działu, np. Magazyn" style="flex:1;min-width:0" onkeydown="if(event.key==='Enter')addDept()">
          <button class="btn" onclick="addDept()">Dodaj dział</button></div>
        <div class="row" id="deptList" style="margin-top:12px;gap:8px"></div>
        <p class="hint">Działy i przypisania zapisuje panel (nie kontroler) - są wspólne dla wszystkich kontrolerów. Pracownika rozpoznaje numer karty, więc przypisanie działa także w logu przejść i w raporcie czasu pracy.</p>
      </div>
    </div>
    <div class="card" data-role="operator">
      <div class="ch"><h2>Dodaj wiele kart naraz</h2><div class="spacer"></div>
        <span class="muted small">lista wklejona z arkusza albo spisana ręcznie</span></div>
      <p class="lead" style="margin:0">Jedna osoba w wierszu: <b>numer karty i nazwa właściciela</b>, oddzielone
        tabulatorem, średnikiem, przecinkiem albo spacją (kolejność dowolna - panel rozpozna, która część jest numerem).
        Wszystkie karty z listy można od razu przypisać do jednego działu.</p>
      <div class="form" style="margin-top:12px">
        <label class="fld" style="flex:1;min-width:280px"><span class="lbl">Lista kart</span>
          <textarea id="bulkList" rows="8" spellcheck="false" style="width:100%;font-family:ui-monospace,Consolas,monospace"
            placeholder="123456;Jan Kowalski&#10;123457;Anna Nowak&#10;123458  Piotr Wiśniewski"></textarea></label>
        <div style="display:flex;flex-direction:column;gap:10px;min-width:220px">
          <label class="fld"><span class="lbl">Dział dla wszystkich z listy</span>
            <select id="bulkDept"></select></label>
          <label class="fld" title="Ta sama data dla wszystkich kart z listy - np. ekipa firmy zewnętrznej na czas remontu"><span class="lbl">Ważne do (opcjonalnie)</span>
            <input type="date" id="bulkValidTo"></label>
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="bulkCheckBtn" onclick="bulkPreview(this)">Sprawdź listę</button>
        <button class="btn ghost" onclick="$('#bulkList').value='';bulkClose()">Wyczyść</button>
      </div>
      <div id="bulkBox" hidden style="margin-top:14px"></div>
      <p class="hint">Karty, które są już w kontrolerze, nie są dodawane po raz drugi - dostają z listy sam dział,
        a ich nazwę w kontrolerze zmienia się przyciskiem „Edytuj / dostęp”. Każda nowa karta dostaje dostęp do wszystkich drzwi (jak przy dodawaniu pojedynczo); uprawnienia zmienisz
        potem w „Edytuj / dostęp”. Numery <b>powyżej 65535</b> panel sprawdza tak samo jak przy dodawaniu pojedynczej karty.</p>
    </div>
    <div class="card">
      <div class="ch"><h2>Użytkownicy</h2><span class="muted small" id="usersCount"></span></div>
      <div class="toolbar">
        <label class="fld"><span class="lbl">Dział</span><select id="deptFilter" onchange="renderUsers()"></select></label>
        <label class="fld" style="flex:1;min-width:180px"><span class="lbl">Szukaj (nazwa lub nr karty)</span>
          <input type="text" id="search" style="width:100%" placeholder="Wpisz i naciśnij Enter" onkeydown="if(event.key==='Enter')loadUsers()"></label>
        <button class="btn ghost" onclick="loadUsers()">Szukaj</button>
        <button class="btn ghost" onclick="document.getElementById('search').value='';loadUsers()">Wyczyść</button>
      </div>
      <div class="row" id="selBar" data-role="operator" hidden style="margin:0 0 10px;align-items:flex-end;gap:10px;flex-wrap:wrap">
        <b id="selCount" style="padding-bottom:9px"></b>
        <label class="fld"><span class="lbl">Przypisz zaznaczone do działu</span><select id="selDept"></select></label>
        <button class="btn" id="selBtn" onclick="assignSelected(this)">Przypisz</button>
        <button class="btn ghost" onclick="clearSel()">Odznacz</button>
      </div>
      <div class="tw"><table><thead><tr>
        <th data-role="operator" style="width:26px"><input type="checkbox" id="selAll" onchange="selectAllUsers(this)" title="Zaznacz wszystkich z listy poniżej"></th>
        <th>User ID</th><th>Nr karty</th><th>Nazwa</th><th>Dział</th><th>Ważność</th><th></th></tr></thead>
        <tbody id="usersBody"></tbody></table></div>
      <p class="hint" data-role="operator" style="margin:10px 0 0">Zaznacz osoby po lewej (albo wszystkie znaczkiem
        w nagłówku tabeli) i przypisz je do działu jednym kliknięciem - przydaje się po dodaniu listy kart bez działu.
        Filtr „Bez działu” pokazuje właśnie te osoby.</p>
      <p class="small warn-t" id="usersNote" style="margin:10px 0 0" hidden></p>
      <details class="help"><summary>Ważność i blokada kart - jak działają</summary>
        <div class="hb"><ul>
          <li><b>Ważność</b> (daty „od” i „do”) zapisuje się w pamięci kontrolera - karta sama przestaje działać po tym dniu, także gdy panel jest wyłączony. Dobre dla gości, praktykantów i firm zewnętrznych.</li>
          <li><b>Blokada</b> (np. zgubiona karta, odejście z pracy) odbiera karcie dostęp do wszystkich drzwi, ale jej nie usuwa - log przejść i czas pracy zachowują nazwisko. Panel pamięta poprzednie uprawnienia i przywraca je przy odblokowaniu. Przy kilku połączonych kontrolerach można zablokować kartę na wszystkich naraz.</li>
          <li>Karty dodane stroną kontrolera mają fabrycznie ważność do <b>31.12.2029</b> („bez terminu” w panelu oznacza tę datę). Własna strona kontrolera zna lata tylko do 2029.</li>
          <li>Obie funkcje używają kanału UDP 60000 kontrolera. Sprawdzone na atrapie kontrolera - na sprzęcie przetestuj kartą z datą „do” wczoraj.</li>
        </ul></div></details>
    </div>
    <div class="card" id="dirCard">
      <div class="ch"><h2>Spis kart panelu</h2><span class="muted small" id="dirCount"></span><div class="spacer"></div>
        <label class="small muted" style="white-space:nowrap"><input type="checkbox" id="dirAll" onchange="renderDirectory()"> pokaż też karty zapisane w kontrolerach</label>
        <button class="btn ghost sm" onclick="loadDirectory()">Odśwież</button></div>
      <p class="lead" style="margin:0">Panel pamięta nazwę i dział każdej karty, którą kiedykolwiek widział - wspólnie dla wszystkich
        kontrolerów. Usunięcie karty z kontrolera tego spisu <b>nie czyści</b> (dzięki temu log i czas pracy zachowują nazwisko),
        więc ta sama karta przyłożona do innego kontrolera dalej pokaże się w logu z imieniem. Kartę, której już nie ma
        w żadnym kontrolerze, możesz tu usunąć ze spisu.</p>
      <div class="tw" style="margin-top:12px"><table><thead><tr>
        <th>Nr karty</th><th>Nazwa</th><th>Dział</th><th>W kontrolerach</th><th>Ostatnio w logu</th><th></th></tr></thead>
        <tbody id="dirBody"></tbody></table></div>
      <p class="small warn-t" id="dirNote" style="margin:10px 0 0" hidden></p>
      <p class="hint" style="margin:10px 0 0">Usunięcie ze spisu kasuje tylko nazwę i dział w panelu. Wpisy w logu zostają, ale ta karta
        pokaże się w nich bez nazwy (chyba że kontroler zapisał nazwę w samym rekordzie). Panel sprawdza tylko
        <b>połączone</b> kontrolery - jeśli karta jest w kontrolerze, z którym panel teraz nie jest połączony, nazwa wróci
        przy następnym wczytaniu jego użytkowników.</p>
    </div>
    <div class="card" id="backupCard" data-role="operator">
      <div class="ch"><h2>Kopia zapasowa użytkowników</h2><div class="spacer"></div>
        <button class="btn ghost sm" onclick="downloadBackup(this)">⬇️ Pobierz kopię</button>
        <span data-role="admin"><button class="btn ghost sm" id="restorePick" onclick="$('#restoreFile').click()">⬆️ Przywróć z pliku...</button></span>
        <input type="file" id="restoreFile" accept=".json,application/json" hidden onchange="restorePreview(this)"></div>
      <p class="lead" style="margin:0">Plik z numerami kart i nazwami <b>wszystkich</b> użytkowników kontrolera, pogrupowanymi według działów (zapisuje też działy bez osób).
        Kopia <b>nie zawiera</b> uprawnień do drzwi, PIN-ów ani godzin wejścia - zależą od tego, które drzwi są podłączone do którego przekaźnika.</p>
      <div id="restoreBox" hidden style="margin-top:14px"></div>
    </div>
  </section>

  <!-- LOG -->
  <section id="log" class="tab">
    <div class="ph"><div><h1>Log przejść</h1><p>Wejścia, wyjścia i odmowy dostępu. Panel przechowuje kopię logu kontrolera, więc filtry działają także na starszych wpisach.</p></div>
      <label class="small muted" style="white-space:nowrap"><input type="checkbox" id="auto" onchange="toggleAuto()"> Auto-odświeżanie co 5 s</label>
      <button class="btn" id="syncBtn" onclick="refreshLog()">Pobierz nowe wpisy</button></div>
    <div class="card">
      <div class="toolbar">
        <label class="fld"><span class="lbl">Dział</span>
          <select id="fDept" onchange="renderPersonFilter('f');filtersChanged()"></select></label>
        <label class="fld"><span class="lbl">Pracownik</span>
          <select id="fCard" onchange="filtersChanged()" style="min-width:200px"></select></label>
        <label class="fld"><span class="lbl">Od dnia</span>
          <input type="date" id="fFrom" onchange="filtersChanged()"></label>
        <label class="fld"><span class="lbl">Do dnia</span>
          <input type="date" id="fTo" onchange="filtersChanged()"></label>
        <button class="btn ghost" onclick="clearFilters('f')">Wyczyść filtry</button>
      </div>
      <p class="muted small" id="syncInfo" style="margin:0 0 6px"></p>
      <div class="tw"><table><thead><tr>
        <th>#</th><th>Kierunek</th><th>Pracownik</th><th>Dział</th><th>Drzwi</th><th>Status</th><th>Data i czas</th></tr></thead>
        <tbody id="swipeBody"></tbody></table></div>
      <div class="pager">
        <button class="btn ghost sm" onclick="logNav('first')" title="Pierwsza strona">|&lt;</button>
        <button class="btn ghost sm" onclick="logNav('prev')">&lt; Poprzednia</button>
        <span id="pageInfo" class="muted small" style="margin:0 6px"></span>
        <button class="btn ghost sm" onclick="logNav('next')">Następna &gt;</button>
        <button class="btn ghost sm" onclick="logNav('last')" title="Ostatnia strona">&gt;|</button></div>
      <p class="hint" style="margin-top:12px"><span class="e">➡️🚪</span> wejście · <span class="e">🚪➡️</span> wyjście · ⛔ odmowa dostępu · 🔓 otwarcie z panelu · ⚙️ zdarzenie urządzenia (np. restart)</p>
    </div>
  </section>

  <!-- CZAS PRACY -->
  <section id="work" class="tab">
    <div class="ph"><div><h1>Czas pracy</h1><p>Czas pobytu pracowników liczony z odbić kart przy wejściu i wyjściu, z normą, nadgodzinami i spóźnieniami. Bez dat raport liczy bieżący miesiąc.</p></div>
      <button class="btn" id="wtBtn" onclick="loadWorktime()">Przelicz</button>
      <button class="btn ghost" id="wtCsvBtn" onclick="exportWorktime(this)">⬇️ Eksport CSV</button>
      <button class="btn ghost" id="wtPrintBtn" onclick="printWorktime()" title="Miesięczna karta ewidencji dla każdego pracownika z filtra - do druku albo zapisu jako PDF">🖨️ Karta miesięczna</button></div>
    <div class="card">
      <div class="toolbar">
        <label class="fld"><span class="lbl">Miejsce</span>
          <select id="wtPlace" onchange="wtFiltersChanged()"></select></label>
        <label class="fld"><span class="lbl">Dział</span>
          <select id="wDept" onchange="renderPersonFilter('w');wtFiltersChanged()"></select></label>
        <label class="fld"><span class="lbl">Pracownik</span>
          <select id="wCard" onchange="wtFiltersChanged()" style="min-width:200px"></select></label>
        <label class="fld"><span class="lbl">Od dnia</span>
          <input type="date" id="wFrom" onchange="wtFiltersChanged()"></label>
        <label class="fld"><span class="lbl">Do dnia</span>
          <input type="date" id="wTo" onchange="wtFiltersChanged()"></label>
        <button class="btn ghost" onclick="clearFilters('w')">Wyczyść filtry</button>
      </div>
      <p class="small muted" id="wtInfo" style="margin:0"></p>
      <div id="wtBody" class="tw"></div>
      <details class="help"><summary>Jak liczony jest czas pracy</summary>
        <div class="hb"><ul>
          <li>Pobyt = odbicie na czytniku wejścia do odbicia na czytniku wyjścia drzwi, które mają zaznaczoną analizę w zakładce „Drzwi”. Pobyt zaliczany jest do dnia wejścia (nocna zmiana liczy się w dniu rozpoczęcia). Brak odbicia przy wyjściu lub wejściu (albo pobyt dłuższy niż 16 h) jest pokazywany jako uwaga ❓ i nie jest liczony. Kliknij wiersz pracownika, aby zobaczyć godziny z każdego dnia.</li>
          <li><b>Korekta</b> ✍️ - brakujące odbicie (np. zapomniana karta) dopisuje operator z podaniem powodu. Korekta liczy się jak odbicie, jest oznaczona w raporcie, na karcie miesięcznej i w CSV, a jej dodanie i usunięcie trafia do dziennika działań.</li>
          <li><b>Norma</b> = dni robocze do dziś (pn–pt bez świąt ustawowych i wyjątków „brak wejścia” z godzin wejścia) × norma dzienna działu. <b>Saldo</b> = przepracowane − norma. <b>Nadgodziny</b> = czas ponad normę w dni robocze + cały czas w dni wolne.</li>
          <li><b>Spóźnienie</b> - pierwsze wejście dnia później niż początek zmiany działu + tolerancja. Działy bez początku zmiany nie mają spóźnień.</li>
          <li>Raport jest pomocą w ewidencji, nie zastępuje przepisów o czasie pracy (przerwy, doby pracownicze, okresy rozliczeniowe).</li>
        </ul></div></details>
    </div>
    <div class="card" data-role="admin">
      <details id="wsBox"><summary style="cursor:pointer"><b>Normy i początek zmiany działów</b> <span class="muted small">- do salda, nadgodzin i spóźnień</span></summary>
        <div class="form" style="margin-top:14px">
          <label class="fld"><span class="lbl">Norma dzienna (h)</span><input type="number" id="wsNorm" min="0" max="24" step="0.25"></label>
          <label class="fld"><span class="lbl">Tolerancja spóźnienia (min)</span><input type="number" id="wsTol" min="0" max="240"></label>
          <label class="fld"><span class="lbl">&nbsp;</span><span class="small"><input type="checkbox" id="wsPl"> święta ustawowe (PL) to dni wolne</span></label>
        </div>
        <div class="tw"><table><thead><tr><th>Dział</th><th>Norma dzienna (h)</th><th>Początek zmiany</th></tr></thead><tbody id="wsDepts"></tbody></table></div>
        <p class="hint">Puste pole normy = norma domyślna. Pusty początek zmiany = bez liczenia spóźnień w tym dziale.</p>
        <button class="btn" onclick="saveWorkSettings(this)">Zapisz ustawienia</button>
      </details>
    </div>
  </section>

  <!-- DRZWI -->
  <section id="door" class="tab">
    <div class="ph"><div><h1>Drzwi</h1><p>Nazwy drzwi, czas otwarcia zamka i to, na których drzwiach liczony jest czas pracy.</p></div></div>
    <div class="note warn" id="doorVerifyNote" hidden>Profil tego modelu nie został zweryfikowany na sprzęcie - kody ustawień drzwi #3–#4 są wyznaczone według schematu drzwi #1–#2.</div>
    <div class="card">
      <div class="ch"><h2>Parametry drzwi</h2></div>
      <div class="tw"><table><thead><tr><th>Drzwi</th><th>Nazwa</th><th>Czas otwarcia (s)</th><th>Czytniki</th>
        <th title="Zapisywane w panelu, nie w kontrolerze">Analiza czasu pracy</th><th></th></tr></thead>
        <tbody id="doorParamsBody"></tbody></table></div>
      <p class="small" id="trackNote" style="margin:10px 0 0"></p>
    </div>
    <div class="card" data-online>
      <div class="ch"><h2>Ostrzeżenie o otwartych drzwiach</h2></div>
      <p class="lead" style="margin:4px 0 12px">Kontroler <b>nie wysyła</b> żadnego sygnału, gdy drzwi zostaną otwarte na długo -
        czas otwarcia liczy panel, między zdarzeniami „drzwi otwarte” i „drzwi zamknięte”. Ostrzeżenie pokazuje się
        na pulpicie i w podglądzie na żywo, a przy włączonej regule także w powiadomieniach (e-mail, Telegram, webhook).</p>
      <div class="tw"><table><thead><tr><th>Drzwi</th><th>Pilnuj czasu otwarcia</th><th>Ostrzeż po</th><th>Stan teraz</th></tr></thead>
        <tbody id="doBody"></tbody></table></div>
      <p class="small" id="doNote" style="margin:10px 0 0"></p>
      <p class="hint">Działa tylko przy podłączonym czujniku otwarcia drzwi (kontaktronie) i włączonym <b>rejestrowaniu zdarzeń</b>
        (niżej). Wejście czujnika, do którego nic nie jest podłączone, kontroler czyta jako „otwarte” - takich drzwi nie zaznaczaj.
        Panel musi być połączony z kontrolerem (zob. „Łącz sam” w zakładce Kontrolery).</p>
      <div class="ch" style="margin-top:18px"><h3 style="margin:0;font-size:15px">Ostatnie długie otwarcia</h3></div>
      <div class="tw" style="margin-top:8px"><table><thead><tr><th>Drzwi</th><th>Otwarte</th><th>Zamknięte</th><th>Jak długo</th></tr></thead>
        <tbody id="doHist"></tbody></table></div>
      <p class="hint" id="doHistNote"></p>
    </div>
    <div class="card" data-role="admin">
      <h2>Rejestrowanie zdarzeń</h2>
      <p class="lead" style="margin:4px 0 12px">Zapis w logu naciśnięć przycisku wyjścia i zmian stanu drzwi - ustawienie wspólne dla całego urządzenia.</p>
      <div class="row"><select id="events"><option value="1">Włączone</option><option value="2">Wyłączone</option></select>
        <button class="btn" onclick="saveEvents()">Zapisz</button></div>
    </div>
  </section>

  <!-- GODZINY WEJŚCIA -->
  <section id="hours" class="tab">
    <div class="ph"><div><h1>Godziny wejścia</h1>
      <p>W jakich godzinach i dniach pracownicy danego działu mogą wejść. <b>Wyjście działa zawsze.</b></p></div>
      <span class="small" id="ehState"></span></div>
    <div class="note warn" data-offline hidden><b>Tryb offline: tylko jedna zmiana.</b>
      Wszystkie działy, które mają karty w kontrolerze, muszą mieć te same godziny i dni (albo wejście „o każdej porze”) -
      taki harmonogram zapisuje się w liście zadań kontrolera i działa też po zamknięciu panelu.
      Różne godziny dla różnych działów przełącza panel na bieżąco, więc wymagają trybu online; zapis takiej konfiguracji
      zostanie tu odrzucony.</div>
    <div class="note err" id="ehOfflineStale" hidden></div>
    <div class="card">
      <div class="ch"><h2>1. Drzwi z ograniczeniem</h2></div>
      <div class="row" id="ehDoors"></div>
      <p class="hint">Drzwi bez ograniczenia wpuszczają wszystkie karty z dostępem o każdej porze.</p>
    </div>
    <div class="card">
      <div class="ch"><h2>2. Godziny działów</h2></div>
      <p class="lead">Godzina „do” wcześniejsza niż „od” (np. 22:00–06:00) to zmiana przez północ - trwa do rana następnego dnia.</p>
      <div class="tw"><table><thead><tr><th>Dział</th><th>Kart</th><th>Wejście</th><th>Od</th><th>Do</th><th>Dni</th><th title="Według konfiguracji zapisanej na kontrolerze">Teraz</th></tr></thead>
        <tbody id="ehBody"><tr><td colspan="7" class="muted">—</td></tr></tbody></table></div>
      <div class="note" id="ehPlan" style="margin:14px 0 0"></div>
      <details class="help"><summary>Jedna zmiana czy kilka zmian - co to zmienia</summary>
        <div class="hb">
          <p><b>Jedna zmiana</b> - wszystkie działy, które mają pracowników, wchodzą w tych samych godzinach i dniach (albo o każdej porze): godziny zapisują się w kontrolerze i po zapisie <b>panel nie musi być podłączony</b>.</p>
          <p class="warn-t"><b class="warn-t">Więcej niż jedna zmiana</b> - działy z pracownikami mają różne godziny albo któryś ma „brak wejścia”: godziny przełącza panel, więc <b class="warn-t">panel musi być stale podłączony do kontrolera</b>. Gdy nie jest, karty zostają w ostatnim stanie: dział, który akurat mógł wchodzić, wchodzi dalej, a kolejny nie wejdzie, dopóki panel nie wróci. Dlatego <b>tryb offline obsługuje tylko jedną zmianę</b>.</p>
        </div></details>
    </div>
    <div class="card">
      <div class="ch"><h2>3. Dni wolne i wyjątki</h2><span class="small" id="ehHolToday"></span><div class="spacer"></div>
        <span class="row" data-role="admin" style="gap:6px">
          <button class="btn ghost sm" onclick="ehAddHoliday()">+ Dodaj wyjątek</button>
          <select id="ehPlYear" style="padding:5px 8px"></select><button class="btn ghost sm" onclick="ehAddPl(this)">+ Święta ustawowe</button>
          <button class="btn ghost sm" onclick="ehDropPast()">Usuń minione</button></span></div>
      <p class="lead">W wybrane dni działy z wejściem „w godzinach” nie wchodzą albo wchodzą tylko w skróconych godzinach (np. Wigilia 8–12). Działy „o każdej porze” wchodzą jak zwykle, wyjście działa zawsze. Wyjątek dotyczy godzin, które <b>zaczynają się</b> w tym dniu.</p>
      <div class="tw"><table><thead><tr><th>Od dnia</th><th>Do dnia</th><th>Nazwa</th><th>Wejście</th><th>Od</th><th>Do</th><th></th></tr></thead>
        <tbody id="ehHol"><tr><td colspan="7" class="muted">Brak wyjątków.</td></tr></tbody></table></div>
      <p class="hint">Przy jednej zmianie wyjątki trafiają do listy zadań kontrolera (działają bez panelu); każdy wyjątek to kilka dodatkowych zadań. Przy kilku zmianach uwzględnia je panel przy przełączaniu PIN-ów.</p>
    </div>
    <div class="card" data-role="admin">
      <div class="row">
        <button class="btn" id="ehSave" onclick="saveEntryHours(this)">Zapisz na kontrolerze</button>
        <span class="small" id="ehInfo"></span></div>
    </div>
    <div class="card">
      <div class="ch"><h2>Stan na kontrolerze</h2></div>
      <div id="ehWatch" class="small"></div>
      <div id="ehPins" class="small" style="margin-top:6px"></div>
      <div id="ehPasses" class="small muted" style="margin-top:6px"></div>
      <details class="help"><summary>Jak to działa i o czym pamiętać</summary>
        <div class="hb"><ul>
          <li>Poza godzinami drzwi są w trybie <b>„karta + PIN na wejściu”</b>. Czytnik bez klawiatury nie przekaże PIN-u, więc kontroler wpuszcza wtedy tylko karty z <b>PIN-em 0</b> - o nie nie pyta. Wyjście nie wymaga PIN-u.</li>
          <li><b>Jedna zmiana:</b> kontroler sam przełącza drzwi o godzinie „od” (bez PIN-u) i „do” (z PIN-em); PIN 0 mają na stałe tylko działy „o każdej porze”. <b>Kilka zmian:</b> drzwi są stale w trybie z PIN-em, a panel w godzinach działu ustawia kartom tego działu PIN 0 i po godzinach przywraca 345678.</li>
          <li>Liczą się tylko działy (i „Pracownicy bez działu”), które mają karty w kontrolerze. Gdy przypisanie pracownika zmieni jedną zmianę w kilka (albo odwrotnie), panel sam przepisze listę zadań kontrolera. Karta dodana z pominięciem panelu (np. stroną kontrolera) przy jednej zmianie wejdzie w jej godzinach, dopóki panel się nie połączy i jej nie przeliczy.</li>
          <li>Godziny liczy <b>zegar kontrolera</b> - sprawdź go w górnym pasku i w razie różnicy zsynchronizuj w zakładce System. Przy kilku zmianach panel przełącza PIN-y w ciągu kilku sekund od początku i końca godzin; PIN-y i listę zadań sprawdza też po połączeniu i co 10 minut.</li>
          <li>Dni oznaczają dzień <b>rozpoczęcia</b> godzin: zmiana 22:00–06:00 zaznaczona w piątek trwa do soboty 06:00. Taka sama godzina „od” i „do” (np. 00:00–00:00) to cała doba w zaznaczone dni.</li>
          <li>O pracowniku decyduje dział przypisany w zakładce „Pracownicy i karty”. Nowy dział ma na start „brak wejścia” - ustaw mu godziny i zapisz. Karty bez działu podlegają wierszowi „Pracownicy bez działu”.</li>
          <li>PIN jest jeden na kartę, więc godziny działu są te same na wszystkich drzwiach z ograniczeniem. Uprawnienia kart do drzwi się nie zmieniają - PIN 0 nie otwiera drzwi, do których karta nie ma dostępu. Drzwi bez ograniczenia wpuszczają wszystkie karty z dostępem o każdej porze.</li>
          <li>Karty z PIN-em innym niż 0 i 345678 (np. nadanym programem producenta) panel zostawia - na drzwiach z ograniczeniem nie wejdą. Jeśli czytnik wejścia ma klawiaturę, da się wejść, podając PIN karty.</li>
          <li>Zapasowo, gdy panel jest połączony, otwiera drzwi, jeśli kontroler mimo wszystko odrzuci brakiem PIN-u kartę, która powinna mieć PIN 0.</li>
          <li>Zapis zastępuje <b>całą listę zadań kontrolera</b> (także zadania ustawione np. programem producenta). Kontroler nie udostępnia tej listy do odczytu - panel pokazuje ostatnio zapisaną konfigurację.</li>
          <li>Tryb PIN i PIN 0 sprawdzone na ACB-002. Na innych modelach przetestuj po zapisie: przyłóż kartę do wejścia i do wyjścia w godzinach działu i poza nimi.</li>
        </ul></div></details>
    </div>
  </section>

  <!-- HASŁA I SUPER CARD -->
  <section id="codes" class="tab">
    <div class="ph"><div><h1>Hasła i Super Card</h1>
      <p>Hasła otwarcia wpisywane na klawiaturze czytnika oraz karty włączające tryb dodawania kart. Panel nie pokazuje zapisanych wartości - tylko to, czy slot jest zajęty.</p></div>
      <button class="btn ghost" onclick="loadCodes()">Odczytaj z kontrolera</button></div>
    <div class="card">
      <h2>Super Card (auto-dodawanie kart)</h2>
      <p class="lead" style="margin:4px 0 12px">Przyłożenie Super Card do czytnika przełącza urządzenie w tryb dodawania kart. Wpisanie nowego numeru zastępuje zapisany.</p>
      <div class="tw"><table><thead><tr><th>Slot</th><th>Stan</th><th>Nowy numer</th><th></th></tr></thead>
        <tbody id="scBody"><tr><td colspan="4" class="muted">—</td></tr></tbody></table></div>
      <p class="small warn-t" id="scHint" style="margin:8px 0 0" hidden></p>
      <p class="hint">Numer karty wpisuj <b>bez zer poprzedzających</b>. Jeśli identyfikator karty ma np. 6 cyfr, a na karcie jest nadrukowane <b>0000123456</b>, wpisz tylko <b>123456</b>. Numer <b>powyżej 65535</b> kontroler widzi inaczej niż jest nadrukowany na karcie - przelicznik i wyjaśnienie są w zakładce <b>„Pracownicy i karty”</b>, pod polem dodawania karty.</p>
    </div>
    <div class="card">
      <h2>Hasła otwarcia z klawiatury</h2>
      <p class="lead" style="margin:4px 0 12px">Każde drzwi mają własne 4 sloty, hasło to do 6 cyfr. Część kontrolerów nie ujawnia nawet, czy slot jest zajęty - wtedy stan jest „nieznany”. Hasło można nadpisać lub wyczyścić.</p>
      <div class="note warn">⚠️ Kontroler <b>nie zapisuje błędnych haseł</b> i nie blokuje klawiatury po kolejnych próbach. Udane otwarcie trafia do logu, ale <b>bez informacji, którym hasłem</b> - nie da się ustalić, kto (ani która grupa) wszedł.</div>
      <div class="tw"><table><thead><tr><th>Slot</th><th>Stan</th><th>Nowe hasło (do 6 cyfr)</th><th></th></tr></thead>
        <tbody id="dpBody"></tbody></table></div>
      <details class="help"><summary>Jak kontroler przyjmuje hasło - obserwacje na sprzęcie</summary>
        <div class="hb"><ul>
          <li>Hasła <b>nie zatwierdza się</b> klawiszem. Hasło 6-cyfrowe otwiera drzwi od razu po ostatniej cyfrze, krótsze (np. 4444) - ok. 1 s po ostatniej cyfrze, gdy kontroler uzna, że nic więcej nie zostanie wpisane.</li>
          <li>Przerwa 2–3 s między cyframi nie przerywa wpisywania; dłuższa przerwa kasuje wpisane cyfry i trzeba zacząć od nowa.</li>
          <li>Kontroler nie szuka hasła na końcu dłuższego ciągu: przy haśle 111111 wpisanie 52111111 nie otwiera, przy haśle 4444 - wpisanie 54444. Każda próba zaczyna się od początku.</li>
          <li>Zalecane hasła 6-cyfrowe: otwierają bez opóźnienia i są trudniejsze do zgadnięcia (milion kombinacji zamiast 10 tysięcy przy 4 cyfrach). Nie testowano hasła będącego początkiem innego (np. 4444 i 444412) - przy przerwie po „4444” zadziała zapewne krótsze.</li>
          <li>W logu otwarcie hasłem wygląda zawsze tak samo („otwarcie hasłem”, drzwi, czas) - niezależnie od slotu.</li>
          <li>Sprawdzone na ACB-002 (firmware V6.62), 17.09.2026. Inne modele mogą działać inaczej.</li>
        </ul></div></details>
    </div>
  </section>

  <!-- SYSTEM -->
  <section id="system" class="tab">
    <div class="ph"><div><h1>System</h1><p>Zegar, język, konto administratora i parametry sieciowe kontrolera.</p></div></div>
    <div class="cols2">
      <div class="card">
        <h2>Zegar kontrolera</h2>
        <div id="clockBox" hidden>
          <div class="clockbig devclock">—</div>
          <div class="small muted" id="clockInfo"></div>
        </div>
        <button class="btn ghost" style="margin-top:12px" onclick="syncTime(this)" title="Ustawia zegar kontrolera według czasu serwera panelu (NTP)">🕒 Synchronizuj czas z komputerem</button>
      </div>
      <div class="card">
        <h2>Urządzenie</h2>
        <label class="fld" style="margin-top:12px"><span class="lbl">Język interfejsu urządzenia</span>
          <span class="row"><select id="lang"><option value="english">Angielski</option><option value="chinese">Chiński</option></select>
          <button class="btn" onclick="saveLang()">Zapisz</button></span></label>
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--line2)">
          <button class="btn danger" onclick="doReboot()">Restart urządzenia</button>
          <p class="hint">Chwilowa przerwa w działaniu drzwi i panelu.</p></div>
      </div>
    </div>
    <div class="card">
      <h2>Konto administratora</h2>
      <p class="lead" style="margin:4px 0 12px">Po zapisaniu panel sprawdzi nowe dane i automatycznie zacznie ich używać.</p>
      <div class="note warn" id="admDefaultNote" hidden>Kontroler używa domyślnych danych logowania - pola „Obecny login” i „Obecne hasło” zostały wypełnione. Wpisz tylko nowe dane.</div>
      <div class="form">
        <label class="fld"><span class="lbl">Obecny login</span><input type="text" id="oldName"></label>
        <label class="fld"><span class="lbl">Obecne hasło</span><input type="password" id="oldPwd"></label>
      </div>
      <div class="form">
        <label class="fld"><span class="lbl">Nowy login</span><input type="text" id="admNewName"></label>
        <label class="fld"><span class="lbl">Nowe hasło</span><input type="password" id="newPwd"></label>
        <label class="fld"><span class="lbl">Powtórz nowe hasło</span><input type="password" id="newPwd2"></label>
      </div>
      <button class="btn" onclick="saveAdmin()">Zmień dane administratora</button>
    </div>
    <div class="card danger">
      <h2>Parametry sieciowe</h2>
      <div class="note warn" style="margin-top:12px">Po zapisaniu kontroler zrestartuje się (ok. minuty). <b>Możesz zostać na tej stronie</b> -
        panel sam połączy się z kontrolerem pod nowym adresem, a do tego czasu status może pokazywać błąd połączenia.
        Jeśli kontroler jest na liście zapisanych kontrolerów, jego adres IP zmieni się tam automatycznie.
        Nowy adres musi być w sieci komputera z panelem i nie może być zajęty przez inne urządzenie.</div>
      <div class="form">
        <label class="fld"><span class="lbl">Adres IP</span><input type="text" id="netIp"></label>
        <label class="fld"><span class="lbl">Brama</span><input type="text" id="netGw"></label>
        <label class="fld"><span class="lbl">Maska (informacyjnie)</span><input type="text" id="netMask" disabled></label>
      </div>
      <button class="btn danger" onclick="saveNetwork()">Zmień adres IP</button>
    </div>
    <div class="card danger">
      <h2>Reset do ustawień domyślnych</h2>
      <p class="small" style="margin:10px 0 8px">Operacja jest <b class="err-t">nieodwracalna</b>. Zostaną wykonane kolejno:</p>
      <ul class="small" style="margin:0 0 10px;padding-left:20px">
        <li>usunięcie <b>wszystkich użytkowników i kart</b>,</li>
        <li>wyczyszczenie <b>wszystkich haseł otwarcia</b> z klawiatury (4 sloty na każde drzwi) i <b>Super Card</b> (2 sloty),</li>
        <li>zmiana danych logowania na login <b>abc</b> i hasło <b>654321</b>,</li>
        <li>usunięcie kontrolera z listy zapisanych kontrolerów.</li>
      </ul>
      <p class="muted small">Pozostałe ustawienia (nazwa drzwi, czas otwarcia, adres IP, język, rejestr zdarzeń) nie są zmieniane. Usuwanie wielu kart może potrwać kilka minut - nie zamykaj panelu.</p>
      <div class="note">Przed resetem <a href="#" onclick="downloadBackup();return false">pobierz kopię zapasową użytkowników</a> - karty z nazwami i działy przywrócisz potem w zakładce „Pracownicy i karty”.</div>
      <div class="row">
        <input type="text" id="resetConfirm" placeholder="Wpisz RESET, aby potwierdzić" style="width:240px" autocomplete="off">
        <button class="btn danger" id="resetBtn" onclick="factoryReset(this)">Resetuj kontroler</button>
      </div>
      <p class="small" id="resetInfo" style="margin:10px 0 0"></p>
    </div>
  </section>

  <!-- POWIADOMIENIA -->
  <section id="notify" class="tab">
    <div class="ph"><div><h1>Powiadomienia</h1>
      <p>Wiadomości o ważnych zdarzeniach przy drzwiach: e-mail, Telegram albo webhook (Slack, Microsoft Teams, Google Chat, własny system). Zdarzenia przy drzwiach panel widzi tylko u połączonych kontrolerów, więc musi być włączony i połączony (zob. „Łącz sam” w zakładce Kontrolery).</p></div>
      <button class="btn ghost" onclick="notifyTest(this)">Wyślij test</button>
      <button class="btn" onclick="notifySave(this)">Zapisz</button></div>
    <div class="cols2">
      <div class="card">
        <div class="ch"><h2>E-mail (SMTP)</h2><div class="spacer"></div><label class="small"><input type="checkbox" id="nEmailOn"> włączony</label></div>
        <div class="form">
          <label class="fld"><span class="lbl">Serwer SMTP</span><input type="text" id="nHost" placeholder="smtp.example.pl"></label>
          <label class="fld"><span class="lbl">Port</span><input type="number" id="nPort" placeholder="587"></label>
          <label class="fld"><span class="lbl">Szyfrowanie</span><select id="nSec"><option value="starttls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option><option value="none">brak</option></select></label>
        </div>
        <div class="form">
          <label class="fld"><span class="lbl">Użytkownik</span><input type="text" id="nUser" autocomplete="off"></label>
          <label class="fld"><span class="lbl">Hasło</span><input type="password" id="nPass" autocomplete="new-password"></label>
        </div>
        <div class="form">
          <label class="fld"><span class="lbl">Nadawca</span><input type="text" id="nFrom" placeholder="panel@firma.pl"></label>
          <label class="fld"><span class="lbl">Odbiorcy (po przecinku)</span><input type="text" id="nTo" placeholder="kierownik@firma.pl"></label>
        </div>
      </div>
      <div class="card">
        <div class="ch"><h2>Telegram</h2><div class="spacer"></div><label class="small"><input type="checkbox" id="nTgOn"> włączony</label></div>
        <div class="form">
          <label class="fld"><span class="lbl">Token bota</span><input type="password" id="nTgToken" autocomplete="new-password"></label>
          <label class="fld"><span class="lbl">ID czatu</span><input type="text" id="nTgChat" placeholder="np. -1001234567890"></label>
        </div>
        <p class="hint" style="margin-top:0">Bota tworzy się u @BotFather; ID czatu podaje np. @userinfobot (dla grupy: dodaj bota do grupy).</p>
        <div class="ch" style="margin-top:16px"><h2>Webhook</h2><div class="spacer"></div><label class="small"><input type="checkbox" id="nWhOn"> włączony</label></div>
        <label class="fld"><span class="lbl">Adres (POST JSON z polem „text”)</span><input type="text" id="nWhUrl" style="width:100%" placeholder="https://hooks.slack.com/services/..."></label>
      </div>
    </div>
    <div class="card">
      <h2>Kiedy powiadamiać</h2>
      <div class="tw" style="margin-top:10px"><table><tbody id="nRules"></tbody></table></div>
      <div class="row" style="margin-top:12px"><span class="small">Tego samego powiadomienia (ta sama karta, te same drzwi) nie wysyłaj częściej niż co</span>
        <input type="number" id="nCool" min="0" max="1440" style="width:80px"><span class="small">min</span></div>
      <p class="hint">Hasło SMTP i token bota są zapisane w bazie panelu na tym komputerze i nie wracają do przeglądarki - puste pole przy zapisie zostawia zapisaną wartość. Kody zdarzeń alarmowych pochodzą z dokumentacji protokołu WG i nie były sprawdzane na sprzęcie ACB.</p>
    </div>
    <div class="card">
      <h2>Ostatnio wysłane</h2>
      <div class="tw" style="margin-top:10px"><table><thead><tr><th>Czas</th><th>Powiadomienie</th><th>Wynik</th></tr></thead><tbody id="nLog"></tbody></table></div>
    </div>
  </section>

  <!-- DZIENNIK DZIAŁAŃ -->
  <section id="audit" class="tab">
    <div class="ph"><div><h1>Dziennik działań</h1><p>Kto, kiedy i z jakiego komputera zmienił coś w panelu albo w kontrolerze: otwarcia drzwi, karty, blokady, godziny, ustawienia, logowania. Wpisy są przechowywane 2 lata.</p></div></div>
    <div class="card">
      <div class="toolbar">
        <label class="fld"><span class="lbl">Kto</span><select id="aLogin" onchange="auditLoad(1)"><option value="">Wszyscy</option></select></label>
        <label class="fld" style="flex:1;min-width:180px"><span class="lbl">Szukaj</span><input type="text" id="aQ" style="width:100%" placeholder="np. blokada, drzwi, 1040" onkeydown="if(event.key==='Enter')auditLoad(1)"></label>
        <label class="fld"><span class="lbl">Od dnia</span><input type="date" id="aFrom" onchange="auditLoad(1)"></label>
        <label class="fld"><span class="lbl">Do dnia</span><input type="date" id="aTo" onchange="auditLoad(1)"></label>
        <label class="small" style="padding-bottom:9px"><input type="checkbox" id="aErr" onchange="auditLoad(1)"> tylko błędy</label>
        <button class="btn ghost" onclick="auditLoad(1)">Szukaj</button>
      </div>
      <div class="tw"><table><thead><tr><th>Czas</th><th>Kto</th><th>Adres</th><th>Kontroler</th><th>Działanie</th><th>Szczegóły</th></tr></thead><tbody id="aBody"></tbody></table></div>
      <div class="pager"><button class="btn ghost sm" onclick="auditLoad(auditPage-1)">&lt; Nowsze</button>
        <span class="muted small" id="aInfo"></span><button class="btn ghost sm" onclick="auditLoad(auditPage+1)">Starsze &gt;</button></div>
    </div>
  </section>

  <!-- KONTA PANELU -->
  <section id="accounts" class="tab">
    <div class="ph"><div><h1>Konta panelu</h1><p>Kto może zalogować się do panelu i co może zrobić.</p></div>
      <button class="btn" onclick="accEdit(null)">+ Dodaj konto</button></div>
    <div class="card">
      <div class="tw"><table><thead><tr><th>Login</th><th>Imię i nazwisko</th><th>Rola</th><th>Stan</th><th>Ostatnie logowanie</th><th>Sesje</th><th></th></tr></thead><tbody id="accBody"></tbody></table></div>
      <details class="help" open><summary>Role</summary>
        <div class="hb"><ul>
          <li><b>Podgląd</b> - pulpit (na żywo, kto jest w środku), log przejść, lista kart, czas pracy i wydruki. Nie otwiera drzwi i niczego nie zmienia.</li>
          <li><b>Operator</b> - to co podgląd oraz otwieranie drzwi, dodawanie i edycja kart, ważność i blokady kart, działy, korekty czasu pracy, pobieranie kopii użytkowników.</li>
          <li><b>Administrator</b> - wszystko: połączenia z kontrolerami, godziny wejścia, drzwi, hasła i Super Card, system kontrolera, przywracanie kopii, konta panelu, powiadomienia, dziennik działań, ustawienia panelu.</li>
        </ul>
        <p>Zmiana hasła albo wyłączenie konta wylogowuje jego sesje. Po 5 nieudanych próbach logowania login i adres są blokowane na minutę (kolejne blokady coraz dłuższe, do 15 min).</p></div></details>
    </div>
  </section>

  <!-- USTAWIENIA PANELU -->
  <section id="settings" class="tab">
    <div class="ph"><div><h1>Ustawienia panelu</h1><p>Automatyczna synchronizacja zegarów, kopie zapasowe, czyszczenie logów i bezpieczeństwo połączenia z panelem.</p></div>
      <button class="btn" onclick="maintSave(this)">Zapisz</button></div>
    <div class="note" data-offline hidden><b>Tryb offline:</b> synchronizacja zegara i codzienna kopia działają tylko wtedy,
      gdy panel jest uruchomiony - jeśli o ustawionej godzinie program będzie zamknięty, kopia się nie wykona.
      Przy doraźnej pracy pewniejszy jest przycisk <b>„Wykonaj kopię teraz”</b> przed zamknięciem programu.</div>
    <div class="cols2">
      <div class="card">
        <h2>Zegary kontrolerów</h2>
        <label class="small" style="display:block;margin:12px 0"><input type="checkbox" id="mClock"> Synchronizuj zegar połączonych kontrolerów z zegarem tego komputera</label>
        <div class="form">
          <label class="fld"><span class="lbl">Gdy różnica większa niż (s)</span><input type="number" id="mDrift" min="2" max="600"></label>
          <label class="fld"><span class="lbl">Sprawdzaj co (h)</span><input type="number" id="mHours" min="1" max="168"></label>
        </div>
        <div id="mClocks" class="small"></div>
        <p class="hint">Godziny wejścia i czas pracy liczą się zegarem kontrolera. Sprawdzenie odczytuje zegar przez UDP; synchronizacja używa strony kontrolera i może na chwilę (do minuty) wstrzymać inne operacje na tym kontrolerze.</p>
      </div>
      <div class="card">
        <h2>Kopie zapasowe</h2>
        <label class="small" style="display:block;margin:12px 0"><input type="checkbox" id="mBackup"> Codzienna kopia: baza panelu + użytkownicy każdego połączonego kontrolera</label>
        <div class="form">
          <label class="fld"><span class="lbl">Godzina</span><input type="time" id="mTime"></label>
          <label class="fld"><span class="lbl">Trzymaj ostatnich</span><input type="number" id="mKeep" min="1" max="365"></label>
        </div>
        <div class="row"><button class="btn ghost sm" onclick="maintBackup(this)">Wykonaj kopię teraz</button><span class="small" id="mBackupInfo"></span></div>
        <p class="hint" id="mDir"></p>
        <details class="help"><summary>Pliki kopii</summary><div class="tw"><table><tbody id="mFiles"></tbody></table></div></details>
      </div>
    </div>
    <div class="card">
      <h2>Czyszczenie logów</h2>
      <p class="hint">Usuwa wpisy zapisane w panelu. Kontroler swojego logu wyczyścić nie pozwala (firmware nie ma takiej funkcji, nie robi tego też reset do ustawień domyślnych) - panel zapamiętuje jednak, do kiedy log wyczyszczono, i tych wpisów z kontrolera już ponownie nie pobiera.</p>
      <div class="tw"><table><thead><tr><th></th><th>Log</th><th>Wpisów</th><th>Najstarszy</th><th>Najnowszy</th></tr></thead><tbody id="lgKinds"></tbody></table></div>
      <div class="form" style="margin-top:12px">
        <label class="fld"><span class="lbl">Zakres</span><select id="lgMode" onchange="lgScope()"><option value="before">Starsze niż data</option><option value="all">Cały log</option></select></label>
        <label class="fld" id="lgDateFld"><span class="lbl">Usuń wpisy sprzed dnia</span><input type="date" id="lgBefore" onchange="lgPreview()"></label>
        <label class="fld"><span class="lbl">Kontroler (log przejść, zdarzenia)</span><select id="lgCtrl" onchange="lgPreview()"></select></label>
      </div>
      <div class="row"><button class="btn danger sm" id="lgBtn" onclick="lgClear(this)" disabled>Wyczyść</button><span class="small" id="lgInfo"></span></div>
      <p class="hint">Przed usunięciem panel zapisuje kopię całej bazy w katalogu kopii (plik <code>przed-czyszczeniem-logow_…</code>, trzymane 5 ostatnich). Wyczyszczony log przejść to też mniej danych w <b>Czasie pracy</b> - raporty za usunięty okres będą puste. Samo czyszczenie zostaje odnotowane w dzienniku działań, także gdy czyścisz dziennik.</p>
      <div class="small" id="lgCleared"></div>
    </div>
    <div class="card">
      <h2>Bezpieczeństwo połączenia</h2>
      <div class="hb small" style="margin-top:10px">
        <p><b>Przeglądarka → panel</b> może działać po HTTPS: uruchom panel ze zmiennymi <code>ACS_TLS_CERT</code> i <code>ACS_TLS_KEY</code> (pliki PEM certyfikatu i klucza) albo postaw go za serwerem HTTPS (np. Caddy, nginx) z <code>ACS_TRUST_PROXY=1</code>. Bez tego hasła do panelu idą w sieci otwartym tekstem.</p>
        <p><b>Panel → kontroler</b> zawsze idzie po HTTP i UDP bez szyfrowania - firmware kontrolera nie obsługuje HTTPS. Chroni tylko odizolowanie: kontroler w osobnej sieci / VLAN dostępnej wyłącznie dla komputera z panelem, najlepiej panel na małym komputerze podłączonym do kontrolera bezpośrednio kablem.</p>
        <p id="mTls"></p>
      </div>
    </div>
  </section>
</main>
</div>
<div id="toast"></div>
<dialog id="blockDlg"><form method="dialog">
  <h2 id="blockDlgTitle">Zablokuj kartę</h2>
  <p class="muted small" style="margin:-6px 0 12px">Karta straci dostęp do wszystkich drzwi, ale zostanie w kontrolerze. Odblokowanie przywróci poprzednie uprawnienia.</p>
  <label class="fld"><span class="lbl">Powód (widoczny w panelu i w dzienniku)</span><input type="text" id="blockReason" maxlength="120" style="width:100%" placeholder="np. zgubiona karta"></label>
  <label class="small" id="blockAllRow" style="display:block;margin:4px 0 14px"><input type="checkbox" id="blockAll" checked> Zablokuj też na pozostałych połączonych kontrolerach</label>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn danger" value="ok">Zablokuj</button></div>
</form></dialog>
<dialog id="cardDlg"><form method="dialog">
  <h2 id="cardDlgTitle">Zmień numer karty</h2>
  <p class="small warn-t" style="margin:-6px 0 12px" id="cardDlgWarn"></p>
  <label class="fld"><span class="lbl">Nowy numer karty - tak, jak widzi go kontroler</span>
    <input type="text" id="cardDlgNew" inputmode="numeric" placeholder="same cyfry" style="width:100%" oninput="cardHint('#cardDlgNew','#cardDlgHint')"></label>
  <div class="row" style="margin:6px 0"><button type="button" class="btn ghost sm" onclick="cardPickDenied(this,'#cardDlgNew','#cardDlgHint')">📥 Weź z ostatniej odmowy</button>
    <span class="muted small">przyłóż nową kartę do czytnika - kontroler ją odrzuci, a panel weźmie jej numer</span></div>
  <p class="small warn-t" id="cardDlgHint" style="margin:6px 0" hidden></p>
  <details class="help" style="margin:8px 0"><summary>Jak obliczyć numer z nadruku na karcie</summary><div class="hb">
    <ol style="margin:4px 0 8px 18px;padding:0">
      <li>Numer nadrukowany na karcie <b>do 65535</b> - wpisz go bez zmian (bez zer na początku).</li>
      <li>Większy: podziel go przez <b>65536</b>. Część całkowita to <b>kod obiektu</b>, reszta z dzielenia to <b>numer</b>.</li>
      <li>Numer w kontrolerze = <b>kod obiektu × 100000 + numer</b>. Przykład: 99999 ÷ 65536 = 1 reszty 34463 → 1 × 100000 + 34463 = <b>134463</b>.</li>
      <li>Najpewniej bez liczenia: przycisk <b>„Weź z ostatniej odmowy”</b> albo numer z logu przejść.</li>
    </ol>
    <div class="row" style="align-items:flex-end;margin:6px 0">
      <label class="fld"><span class="lbl">Nadruk na karcie</span><input type="text" id="wgdCard" inputmode="numeric" placeholder="np. 99999" oninput="wgCalc('card','wgd')" style="width:150px"></label>
      <span class="muted" style="padding-bottom:9px">⇄</span>
      <label class="fld"><span class="lbl">Numer w kontrolerze</span><input type="text" id="wgdCtrl" inputmode="numeric" placeholder="np. 134463" oninput="wgCalc('ctrl','wgd')" style="width:150px"></label>
      <button type="button" class="btn ghost sm" style="margin-bottom:4px" onclick="if($('#wgdCtrl').value){$('#cardDlgNew').value=$('#wgdCtrl').value;cardHint('#cardDlgNew','#cardDlgHint');}">Użyj ↑</button>
    </div><p id="wgdMsg" class="small"></p></div></details>
  <p class="muted small" style="margin:8px 0 14px">Nowa karta dostaje te same drzwi, daty ważności i PIN. Stara karta zostaje usunięta z kontrolera
    i <b>od razu przestaje otwierać drzwi</b>. Jej dotychczasowe odbicia w czasie pracy i „kto w środku” liczą się tej samej osobie.</p>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn danger" value="ok">Zmień kartę</button></div>
</form></dialog>
<dialog id="replDlg"><form method="dialog">
  <h2>Czy to wymiana karty?</h2>
  <p class="muted small" id="replInfo" style="margin:-6px 0 12px"></p>
  <div id="replList" style="margin:0 0 12px"></div>
  <p class="muted small" style="margin:0 0 14px">„Wymiana karty” - stara karta traci dostęp (jeśli jest w kontrolerze), nowa przejmuje jej drzwi,
    daty ważności, PIN i dział, a czas pracy liczy obie karty jako jedną osobę.<br>„Osobna karta” - dodaje nową kartę jak dotąd, stara zostaje bez zmian.</p>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn ghost" value="add">Osobna karta</button>
    <button class="btn danger" value="replace">Wymiana karty</button></div>
</form></dialog>
<dialog id="corrDlg"><form method="dialog">
  <h2>Korekta czasu pracy</h2>
  <p class="muted small" id="corrWho" style="margin:-6px 0 12px"></p>
  <div class="form">
    <label class="fld"><span class="lbl">Odbicie</span><select id="corrReader"><option value="in">wejście</option><option value="out">wyjście</option></select></label>
    <label class="fld"><span class="lbl">Data i godzina</span><input type="datetime-local" id="corrTime" required></label>
  </div>
  <label class="fld"><span class="lbl">Powód (zostanie w raporcie)</span><input type="text" id="corrNote" maxlength="200" style="width:100%" required placeholder="np. zapomniana karta - potwierdził kierownik"></label>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Dopisz</button></div>
</form></dialog>
<dialog id="accDlg"><form method="dialog">
  <h2 id="accDlgTitle">Konto panelu</h2>
  <label class="fld"><span class="lbl">Login</span><input type="text" id="accLogin" maxlength="40" style="width:100%" required></label>
  <label class="fld"><span class="lbl">Imię i nazwisko</span><input type="text" id="accName" maxlength="60" style="width:100%"></label>
  <label class="fld"><span class="lbl">Rola</span><select id="accRole" style="width:100%"><option value="viewer">Podgląd</option><option value="operator">Operator</option><option value="admin">Administrator</option></select></label>
  <label class="fld"><span class="lbl" id="accPwdLbl">Hasło</span><input type="password" id="accPwd" autocomplete="new-password" style="width:100%" minlength="8"></label>
  <label class="small" style="display:block;margin:4px 0 14px"><input type="checkbox" id="accActive" checked> Konto aktywne</label>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Zapisz</button></div>
</form></dialog>
<dialog id="pwdDlg"><form method="dialog">
  <h2>Zmień hasło do panelu</h2>
  <label class="fld"><span class="lbl">Obecne hasło</span><input type="password" id="pwOld" autocomplete="current-password" style="width:100%"></label>
  <label class="fld"><span class="lbl">Nowe hasło (co najmniej 8 znaków)</span><input type="password" id="pwNew" autocomplete="new-password" style="width:100%"></label>
  <label class="fld"><span class="lbl">Powtórz nowe hasło</span><input type="password" id="pwNew2" autocomplete="new-password" style="width:100%"></label>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Zmień hasło</button></div>
</form></dialog>
<dialog id="userDlg"><form method="dialog">
  <h2 id="userDlgTitle">Użytkownik</h2>
  <label class="fld"><span class="lbl">Nazwa</span>
    <input type="text" id="userDlgName" maxlength="32" style="width:100%"></label>
  <div class="lbl muted small" style="margin:4px 0">Dostęp do drzwi</div>
  <div id="userDlgDoors" style="margin:0 0 14px"></div>
  <div id="userDlgValid">
    <div class="lbl muted small" style="margin:4px 0">Ważność karty</div>
    <div class="row" style="flex-wrap:nowrap"><input type="date" id="userDlgFrom" style="flex:1;min-width:0"> – <input type="date" id="userDlgTo" style="flex:1;min-width:0"></div>
    <div class="row small" style="margin:6px 0 14px;gap:6px"><span class="muted">szybko:</span>
      <button type="button" class="iconbtn" onclick="vQuick(0)">bez terminu</button>
      <button type="button" class="iconbtn" onclick="vQuick(1)">do jutra</button>
      <button type="button" class="iconbtn" onclick="vQuick(7)">+7 dni</button>
      <button type="button" class="iconbtn" onclick="vQuick(30)">+30 dni</button></div>
  </div>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Zapisz</button></div>
</form></dialog>
<dialog id="nameDlg"><form method="dialog">
  <h2 id="nameDlgTitle">Zapisz kontroler</h2>
  <p class="muted small" id="nameDlgInfo" style="margin:-6px 0 12px"></p>
  <label class="fld"><span class="lbl" id="nameDlgLbl">Nazwa kontrolera</span>
    <input type="text" id="nameDlgName" maxlength="60" required onkeydown="if(event.key==='Enter'){event.preventDefault();if(this.value.trim())$('#nameDlg').close('ok');}" style="width:100%" placeholder="np. Biuro - wejście główne"></label>
  <label class="small" id="nameDlgPwdRow" style="display:block;margin:4px 0 14px"><input type="checkbox" id="nameDlgPwd" checked>
    Zapamiętaj hasło <span class="muted">(zapisywane bez szyfrowania w pliku na tym serwerze)</span></label>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Zapisz</button></div>
</form></dialog>

<dialog id="ipDlg"><form method="dialog">
  <h2>Ustaw adres IP kontrolera</h2>
  <p class="muted small" id="ipDlgInfo" style="margin:-6px 0 12px"></p>
  <p class="small" style="margin:0 0 12px">Adres zmienia się przez sieć lokalną (UDP, jak w programie producenta) - bez logowania,
    bez zmiany kart i innych ustawień. Wybierz <b>wolny</b> adres w sieci tego komputera, poza pulą DHCP routera.</p>
  <div class="form">
    <label class="fld"><span class="lbl">Nowy adres IP</span><input type="text" id="ipDlgIp" required></label>
    <label class="fld"><span class="lbl">Maska</span><input type="text" id="ipDlgMask" required></label>
    <label class="fld"><span class="lbl">Brama</span><input type="text" id="ipDlgGw"></label>
  </div>
  <div class="row"><div class="spacer"></div>
    <button class="btn ghost" value="cancel" formnovalidate>Anuluj</button>
    <button class="btn" value="ok">Ustaw adres</button></div>
</form></dialog>

<script>
const $=s=>document.querySelector(s);
let autoTimer=null,lastStatus={},connected=false,me=null,appStarted=false,connList=[];
const LEVEL={viewer:1,operator:2,admin:3};
let MODE='online';
function can(r){return !!me&&LEVEL[me.role]>=LEVEL[r];}
const isOffline=()=>MODE==='offline';
// widoczność: data-need = wymaga połączonego kontrolera, data-role = minimalna rola konta panelu,
// data-online = tylko w trybie online (funkcja wymaga panelu działającego bez przerwy),
// data-offline = tylko w trybie offline (wyjaśnienia ograniczeń)
function applyVisibility(){
  document.querySelectorAll('[data-need],[data-role],[data-online],[data-offline]').forEach(el=>{
    el.hidden=(el.hasAttribute('data-need')&&!connected)||(!!el.dataset.role&&!can(el.dataset.role))
      ||(el.hasAttribute('data-online')&&isOffline())||(el.hasAttribute('data-offline')&&!isOffline());});
}
function applyMode(){
  MODE=(authInfo&&authInfo.mode)||'online';
  document.body.classList.toggle('offline',isOffline());
  $('#modeBadge').hidden=!isOffline();
  const off=(authInfo&&authInfo.offline_off)||{};
  $('#offlineOffList').innerHTML=Object.values(off).map(v=>'<li>'+esc(v)+'</li>').join('');
}

document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  if(b.disabled)return;
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  b.classList.add('active'); $('#'+b.dataset.tab).classList.add('active');
  if(b.dataset.tab==='find')loadSaved();
  if(b.dataset.tab==='cards'){loadUsers();restoreResume();bulkResume();loadDirectory();}
  if(b.dataset.tab==='log')openLogTab();
  if(b.dataset.tab==='work')openWorkTab();
  if(b.dataset.tab==='door'||b.dataset.tab==='system')fillForms();
  if(b.dataset.tab==='door')loadDoorOpen();
  if(b.dataset.tab==='hours')loadEntryHours();
  if(b.dataset.tab==='codes')loadCodes();
  if(b.dataset.tab==='dash')loadPresence();
  if(b.dataset.tab==='notify')notifyLoad();
  if(b.dataset.tab==='audit')auditLoad(1);
  if(b.dataset.tab==='accounts')accLoad();
  if(b.dataset.tab==='settings'){maintLoad();lgLoad();}
  try{history.replaceState(null,'','#'+b.dataset.tab);}catch(e){}
});
function toast(m,k){const t=$('#toast');t.textContent=m;t.className='show '+(k||'');setTimeout(()=>t.className='',3800);}
function esc(s){return (s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function api(p,o){o=Object.assign({},o||{});o.headers=Object.assign({'X-ACB':'1'},o.headers||{});
  const r=await fetch(p,o);const j=await r.json().catch(()=>({error:'błędna odpowiedź'}));
  if(r.status===401&&j.login){showAuth();throw new Error(j.error);}
  if(!r.ok||j.error)throw new Error(j.error||('HTTP '+r.status));return j;}
// --- logowanie do panelu ---
let authInfo=null;
async function showAuth(){
  try{authInfo=await (await fetch('/api/auth')).json();}catch(e){authInfo=authInfo||{};}
  if(authInfo.user&&appStarted)return;
  document.body.classList.add('locked');$('#authView').hidden=false;
  $('#setupForm').hidden=!authInfo.needs_setup;$('#loginForm').hidden=!!authInfo.needs_setup;
  $('#suCodeRow').hidden=!!authInfo.local;
  if(authInfo.setup_help)renderSetupHelp(authInfo.setup_help);
  setTimeout(()=>(authInfo.needs_setup?$('#suLogin'):$('#lgLogin')).focus(),50);
}
function renderSetupHelp(h){
  const path=`<code style="user-select:all;word-break:break-all;display:block;margin:4px 0;padding:6px 8px;background:var(--bg);border-radius:6px">${esc(h.file)}</code>`;
  const open={windows:'Otwórz Eksplorator plików, wklej tę ścieżkę w pasek adresu u góry i naciśnij Enter - plik otworzy się w Notatniku.',
    macos:'W Finderze wybierz menu <b>Idź → Idź do folderu</b> (⇧⌘G), wklej tę ścieżkę i naciśnij Enter.',
    linux:'Otwórz go w edytorze tekstu albo w terminalu poleceniem <code>cat</code> z tą ścieżką.'}[h.os]||'';
  const win={windows:'czarnym oknie otwartym przez „Uruchom panel ACB.bat”',macos:'oknie Terminala otwartym przez „Uruchom panel ACB.command”',
    linux:'oknie terminala, w którym uruchomiono panel'}[h.os]||'oknie panelu';
  const steps=[`Na komputerze, na którym działa panel, otwórz plik:${path}${open}`];
  if(h.console)steps.push(`Albo spójrz w okno panelu - kod jest w ${win}, w wierszu „Z innego komputera w sieci potrzebny jest kod”.`);
  else if(h.log)steps.push(`Albo zajrzyj do logu panelu (działa w tle): <code style="user-select:all;word-break:break-all">${esc(h.log)}</code> - wiersz „potrzebny jest kod”.`);
  if(h.local_url)steps.push(`Albo otwórz panel bezpośrednio na tamtym komputerze pod adresem <b>${esc(h.local_url)}</b> - wtedy kod nie jest potrzebny.`);
  $('#suCodeHelp').innerHTML='<b>Gdzie jest kod:</b><ol style="margin:4px 0 6px;padding-left:18px">'+steps.map(x=>`<li style="margin-bottom:6px">${x}</li>`).join('')+'</ol>'
    +'<span class="muted">Kod zmienia się przy każdym uruchomieniu panelu, dopóki nie powstanie pierwsze konto - bierz zawsze aktualny. Po utworzeniu konta plik znika.</span>';
}
async function doLogin(ev){ev.preventDefault();$('#lgBtn').disabled=true;$('#lgErr').textContent='';
  try{await api('/api/login',form({login:$('#lgLogin').value.trim(),pwd:$('#lgPwd').value}));location.reload();}
  catch(e){$('#lgErr').textContent=e.message;$('#lgPwd').select();}finally{$('#lgBtn').disabled=false;}}
async function doSetup(ev){ev.preventDefault();$('#suErr').textContent='';
  if($('#suPwd').value!==$('#suPwd2').value){$('#suErr').textContent='Hasła nie są takie same';return;}
  $('#suBtn').disabled=true;
  try{await api('/api/setup',form({login:$('#suLogin').value.trim(),name:$('#suName').value.trim(),pwd:$('#suPwd').value,code:$('#suCode').value.trim()}));location.reload();}
  catch(e){$('#suErr').textContent=e.message;}finally{$('#suBtn').disabled=false;}}
async function logout(){try{await api('/api/logout',{method:'POST'});}catch(e){}location.reload();}
function renderMe(){
  $('#whoName').textContent=me?(me.name||me.login):'';$('#whoRole').textContent=me?(me.role_name+(authInfo&&!authInfo.auth?' · bez logowania':'')):'';
  $('#whoOut').hidden=$('#whoPwd').hidden=!!(authInfo&&!authInfo.auth);
}
async function changeOwnPwd(){const dlg=$('#pwdDlg');['#pwOld','#pwNew','#pwNew2'].forEach(x=>$(x).value='');dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    if($('#pwNew').value!==$('#pwNew2').value){toast('Nowe hasła nie są takie same','err');return;}
    try{const r=await api('/api/me/password',form({old:$('#pwOld').value,new:$('#pwNew').value}));toast(r.msg,'ok');}
    catch(e){toast('Błąd: '+e.message,'err');}};
  dlg.showModal();}
function form(obj){return {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:Object.entries(obj).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&')};}

// --- wyszukiwanie ---
async function scan(){
  const btn=$('#scanBtn');btn.disabled=true;$('#foundCard').hidden=false;
  $('#scanInfo').innerHTML='<span class="spin"></span> Skanowanie '+esc($('#subnet').value)+' ...';
  $('#foundBody').innerHTML='<tr><td colspan="5" class="muted"><span class="spin"></span> trwa skan...</td></tr>';
  try{
    const d=await api('/api/discover',form({subnet:$('#subnet').value.trim(),user:$('#scanUser').value,pwd:$('#scanPwd').value}));
    $('#scanInfo').textContent='Przeskanowano '+d.subnet+'.';
    $('#foundCount').textContent=d.count+' szt.';
    if(!d.controllers.length){$('#foundBody').innerHTML='<tr><td colspan="5" class="muted">Nie znaleziono kontrolerów.</td></tr>';return;}
    foundCache=d.controllers;scanLocalIp=d.local_ip||'';
    $('#foundBody').innerHTML=d.controllers.map((c,i)=>{
      const lost=c.udp&&c.reachable===false;
      const mdl=c.login_ok?`<span class="pill mdl">${esc(c.model)}</span>${c.verified?'':' <span class="pill unv">profil wstępny</span>'}`
        :lost?'<span class="pill off">adres spoza sieci tego komputera</span>':`<span class="pill unv">${esc(c.model)}</span>`;
      const sv=savedCache.find(s=>(c.device_no&&s.device_no===c.device_no)||s.host===c.host);
      const moved=sv&&sv.host!==c.host?'<br><span class="muted small">zapisany pod adresem '+esc(sv.host)+'</span>':'';
      const net=c.udp?'<br><span class="muted small">maska '+esc(c.udp.mask)+' · MAC '+esc(c.udp.mac)+'</span>':'';
      const setip=c.udp?`<button class="btn${lost?'':' ghost'}" onclick="setIpDialog(${i})">Ustaw adres IP</button> `:'';
      return `<tr><td><b>${esc(c.host)}</b>${sv?'<br><span class="pill on">'+esc(sv.name)+'</span>':''}${moved}${net}</td><td>${mdl}</td><td>${esc(c.device_no)||'—'}</td>
        <td>${esc(c.driver||(c.udp&&c.udp.firmware))||'—'}</td>
        <td style="text-align:right;white-space:nowrap">${setip}${lost?'':`<button class="btn ok" onclick="connectTo('${esc(c.host)}',$('#scanUser').value,$('#scanPwd').value)">Połącz</button>`}</td></tr>`;
    }).join('');
    if(d.controllers.some(c=>c.udp&&c.reachable===false))
      toast('Znaleziono kontroler z adresem spoza sieci tego komputera - użyj „Ustaw adres IP”','err');
  }catch(e){$('#scanInfo').textContent='';$('#foundBody').innerHTML='<tr><td colspan="5" class="muted">Błąd: '+esc(e.message)+'</td></tr>';}
  finally{btn.disabled=false;}
}

let foundCache=[],scanLocalIp='';
function setIpDialog(i){const c=foundCache[i];if(!c||!c.udp)return;
  const pre=(scanLocalIp||'192.168.1.1').split('.').slice(0,3).join('.');
  const last=+c.host.split('.')[3];
  $('#ipDlgInfo').textContent='Nr urządzenia '+c.device_no+' · obecnie '+c.host+' / '+c.udp.mask+' · MAC '+c.udp.mac;
  $('#ipDlgIp').value=c.reachable?c.host:pre+'.'+(last>0&&last<255?last:200);
  $('#ipDlgMask').value=c.reachable?c.udp.mask:'255.255.255.0';
  $('#ipDlgGw').value=c.reachable&&c.udp.gateway!=='0.0.0.0'?c.udp.gateway:pre+'.1';
  const dlg=$('#ipDlg');dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    const ip=$('#ipDlgIp').value.trim();
    toast('Zmiana adresu na '+ip+' - kontroler potwierdza zmianę do 20 s...','');
    try{const r=await api('/api/setip',form({device_no:c.device_no,ip,mask:$('#ipDlgMask').value.trim(),gateway:$('#ipDlgGw').value.trim()}));
      toast(r.msg+(r.saved?'. Poprawiono adres na liście zapisanych.':''),'ok');loadSaved();scan();}
    catch(e){toast('Błąd: '+e.message,'err');}};
  dlg.showModal();$('#ipDlgIp').select();}

function connected_ok(d,label){
  if(connected&&lastStatus.key&&d.active&&d.active.key!==lastStatus.key){toast('Połączono: '+label,'ok');setTimeout(()=>{location.hash='dash';location.reload();},600);return;}
  hideClock();connected=true;wtData=null;$('#wtBody').innerHTML='';$('#wtInfo').textContent='';$('#fCard').value='';$('#wCard').value='';setConnected(d.active);loadSaved();
  showClock(d.active&&d.active.clock,d.active&&d.active.server_time);
  const a=d.active||{};
  if(a.language_error)toast('Połączono: '+label+'. Nie udało się przełączyć urządzenia na angielski ('+a.language_error+') - panel działa także po chińsku.','err');
  else toast('Połączono: '+label+(a.language_switched?'. Przełączono interfejs urządzenia z chińskiego na angielski.':''),'ok');
  goTab('dash');
}
// tryb offline: panel łączy się z zapisanym kontrolerem sam, zaraz po starcie - strona czeka na to
// połączenie, żeby nikt nie musiał odświeżać przeglądarki ani klikać „Połącz”
let offlineWaitTimer=null;
function offlineWaitForConnect(){
  if(!isOffline()||connected||offlineWaitTimer)return;
  $('#offlineWait').hidden=false;
  offlineWaitTimer=setInterval(async()=>{
    if(connected||document.hidden)return;
    try{const a=await api('/api/active');
      if(a.active){clearInterval(offlineWaitTimer);offlineWaitTimer=null;$('#offlineWait').hidden=true;
        location.hash='dash';location.reload();}
    }catch(e){}
  },3000);
}

async function connectTo(host,user,pwd){
  if(!host){toast('Podaj adres IP','err');return;}
  toast('Łączenie z '+host+'...','');
  try{
    const d=await api('/api/connect',form({host,user:user||$('#scanUser').value,pwd:pwd||$('#scanPwd').value}));
    connected_ok(d,(d.active.saved_name||d.active.model)+' ('+host+')');
  }catch(e){toast('Błąd połączenia: '+e.message,'err');}
}

// --- zapisane kontrolery ---
let savedCache=[],savedBusy=false,savedAgain=false;
function onlineCell(o){o=o||{};
  if(o.state==='online')return `<span class="pill on" title="Odpowiada na porcie UDP 60000 (sprawdzono ${o.ago} s temu)">🟢 online</span><br><span class="muted small">od ${esc(o.since)}</span>`;
  if(o.state==='offline')return `<span class="pill off" title="${esc(o.error)} (sprawdzono ${o.ago} s temu)">🔴 offline</span><br><span class="muted small">${o.seen?'ostatnio online '+esc(o.seen):'nie odpowiada od '+esc(o.since)}</span>`;
  if(o.state==='unknown')return `<span class="pill unv" title="${esc(o.error)}">❔ nieznany</span><br><span class="muted small">połącz się raz</span>`;
  return '<span class="muted small"><span class="spin"></span> sprawdzanie</span>';
}
async function loadSaved(){
  if(savedBusy){savedAgain=true;return;}  // odświeżenie w trakcie - powtórz po nim (np. zmiana połączenia)
  savedBusy=true;let d;
  try{d=await api('/api/saved');savedCache=d.saved;connList=d.connected||[];$('#onlinePoll').textContent=Math.round(d.online_poll);}
  catch(e){$('#savedBody').innerHTML='<tr><td colspan="7" class="muted">Błąd: '+esc(e.message)+'</td></tr>';return;}
  finally{savedBusy=false;if(savedAgain){savedAgain=false;setTimeout(loadSaved,0);}}
  renderSwitch();
  $('#connCard').hidden=!connList.length;$('#connCount').textContent=connList.length+' szt.';
  $('#connBody').innerHTML=connList.map(c=>`<tr class="${c.current?'cur':''}"><td><b>${esc(c.name)||'<span class="muted">bez nazwy</span>'}</b>${c.current?' <span class="pill on">oglądany</span>':''}</td>
    <td>${esc(c.host)}</td><td>${esc(c.model)}</td><td class="act">${c.current?'':`<button class="btn ok sm" onclick="switchCtrl('${esc(c.key)}')">Przejdź</button>`}
    ${can('admin')?`<button class="iconbtn del" onclick="disconnectKey('${esc(c.key)}','${esc(c.name||c.host)}')">Rozłącz</button>`:''}</td></tr>`).join('');
  const on=savedCache.filter(s=>s.online&&s.online.state==='online').length;
  $('#savedCount').textContent=savedCache.length?savedCache.length+' szt. · online: '+on:'';
  if(!savedCache.length){$('#savedBody').innerHTML='<tr><td colspan="7" class="muted">Brak zapisanych kontrolerów.</td></tr>';return;}
  const cur=connected?lastStatus.saved_id:'';
  $('#savedBody').innerHTML=savedCache.map(s=>`<tr class="${s.id===cur?'cur':''}">
    <td style="white-space:nowrap">${onlineCell(s.online)}</td>
    <td><b>${esc(s.name)}</b>${s.id===cur?' <span class="pill on">oglądany</span>':s.connected?' <span class="pill mdl">połączony</span>':''}</td>
    <td>${esc(s.host)}</td><td>${esc(s.model)||'—'}</td>
    <td>${esc(s.user)||'—'}${s.has_pwd?'':' <span class="pill unv">bez hasła</span>'}</td>
    <td><input type="checkbox" ${s.autoconnect?'checked':''} ${can('admin')&&s.has_pwd?'':'disabled'} title="${s.has_pwd?'Łącz automatycznie po uruchomieniu panelu':'Wymaga zapamiętanego hasła'}" onchange="setAutoconnect('${esc(s.id)}',this)"></td>
    <td style="text-align:right;white-space:nowrap">
      ${s.connected?(s.id===cur?'':`<button class="btn ok" onclick="connectSaved('${esc(s.id)}')">Przejdź</button>`):can('operator')?`<button class="btn ok" onclick="connectSaved('${esc(s.id)}')">Połącz</button>`:''}
      ${can('admin')?`<button class="iconbtn" onclick="renameSaved('${esc(s.id)}')">Zmień nazwę</button>
      <button class="iconbtn del" onclick="deleteSaved('${esc(s.id)}')">Usuń</button>`:''}</td></tr>`).join('');
}
async function setAutoconnect(id,c){c.disabled=true;
  try{await api('/api/saved/autoconnect',form({id,enabled:c.checked?'1':'0'}));toast('Automatyczne łączenie '+(c.checked?'włączone':'wyłączone'),'ok');}
  catch(e){c.checked=!c.checked;toast('Błąd: '+e.message,'err');}finally{c.disabled=false;}}
function renderSwitch(){const sel=$('#ctrlSwitch');
  sel.hidden=connList.length<2;
  sel.innerHTML=connList.map(c=>`<option value="${esc(c.key)}" ${c.current?'selected':''}>${esc(c.name||c.host)}</option>`).join('');}
async function switchCtrl(key){try{await api('/api/select',form({key}));location.hash='dash';location.reload();}catch(e){toast('Błąd: '+e.message,'err');}}
async function disconnectKey(key,name){if(!confirm('Rozłączyć kontroler „'+name+'”?\nPanel przestanie go obsługiwać (godziny wejścia przy kilku zmianach, zdarzenia, powiadomienia) dla wszystkich użytkowników.'))return;
  try{await api('/api/disconnect',form({key}));toast('Rozłączono','ok');
    const cur=connList.find(c=>c.key===key&&c.current);if(cur)location.reload();else loadSaved();}catch(e){toast('Błąd: '+e.message,'err');}}
function savedById(id){return savedCache.find(s=>s.id===id);}
async function checkOnline(b){b.disabled=true;
  try{await api('/api/saved/check',{method:'POST'});
    savedCache.forEach(s=>s.online={state:'checking'});
    // sprawdzenie offline trwa do ~3 s (dwie próby po 1,5 s)
    await new Promise(r=>setTimeout(r,3500));await loadSaved();}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}
async function connectSaved(id){const s=savedById(id);if(!s)return;
  if(s.connected){const c=connList.find(c=>(s.device_no&&c.device_no===s.device_no)||c.host===s.host);if(c){switchCtrl(c.key);return;}}
  if(!s.has_pwd){  // hasła nie zapamiętano - uzupełnij formularz i poproś o hasło
    $('#directIp').value=s.host;$('#directUser').value=s.user;$('#directPwd').value='';$('#directPwd').focus();$('#directPwd').scrollIntoView({block:'center'});
    toast('Podaj hasło do „'+s.name+'” i kliknij Połącz','');return;}
  toast('Łączenie z „'+s.name+'”...','');
  try{const d=await api('/api/saved/connect',form({id}));connected_ok(d,s.name+' ('+s.host+')');}
  catch(e){toast('Błąd połączenia z „'+s.name+'”: '+e.message,'err');}
}
function nameDialog(title,info,cur,withPwd,label){return new Promise(res=>{
  const dlg=$('#nameDlg');$('#nameDlgTitle').textContent=title;$('#nameDlgInfo').textContent=info;
  $('#nameDlgLbl').textContent=label||'Nazwa kontrolera';
  $('#nameDlgName').value=cur||'';$('#nameDlgPwdRow').hidden=!withPwd;dlg.returnValue='';
  dlg.onclose=()=>res(dlg.returnValue==='ok'?{name:$('#nameDlgName').value.trim(),remember:$('#nameDlgPwd').checked}:null);
  dlg.showModal();$('#nameDlgName').select();});}
async function saveActive(){const s=lastStatus;
  const r=await nameDialog(s.saved_id?'Zmień nazwę kontrolera':'Zapisz kontroler',
    s.host+' · '+(s.model||'')+(s.device_no?' · nr '+s.device_no:''),s.saved_name||s.door_name||'',true);
  if(!r||!r.name)return;
  try{const d=await api('/api/saved/save',form({name:r.name,remember_pwd:r.remember?'1':'0'}));
    setConnected(d.active);loadSaved();toast('Zapisano kontroler „'+r.name+'”','ok');}
  catch(e){toast('Błąd: '+e.message,'err');}}
async function renameSaved(id){const s=savedById(id);if(!s)return;
  const r=await nameDialog('Zmień nazwę kontrolera',s.host,s.name,false);if(!r||!r.name)return;
  try{await api('/api/saved/rename',form({id,name:r.name}));toast('Zmieniono nazwę','ok');await loadSaved();
    if(connected&&lastStatus.saved_id===id){lastStatus.saved_name=r.name;setConnected(lastStatus);}}
  catch(e){toast('Błąd: '+e.message,'err');}}
async function deleteSaved(id){const s=savedById(id);if(!s||!confirm('Usunąć zapisany kontroler „'+s.name+'” ('+s.host+')?\nUrządzenie nie zostanie zmienione.'))return;
  try{await api('/api/saved/delete',form({id}));toast('Usunięto z listy','ok');
    if(connected&&lastStatus.saved_id===id){lastStatus.saved_id='';lastStatus.saved_name='';setConnected(lastStatus);}
    loadSaved();}catch(e){toast('Błąd: '+e.message,'err');}}
async function disconnectActive(){if(!confirm('Rozłączyć z kontrolerem „'+ctrlLabel(lastStatus)+'”?\nPanel przestanie go obsługiwać dla wszystkich użytkowników.'))return;
  let d=null;try{d=await api('/api/disconnect',form({key:lastStatus.key||''}));}catch(e){}
  if(d&&d.connected&&d.connected.length){location.hash='dash';location.reload();return;}
  setDisconnected();toast('Rozłączono','ok');}

function ctrlLabel(s){return s.saved_name||('kontroler '+s.host);}
function renderConn(info,err){
  const c=$('#conn');c.className='conn '+(err?'err':'on');
  $('#dot').className='dot '+(err?'off':'on');
  $('#connK').textContent=err?'Brak odpowiedzi kontrolera':'Połączono z kontrolerem';
  $('#connName').textContent=info.saved_name||'Kontroler bez nazwy';
  $('#connMeta').innerHTML='IP <b>'+esc(info.host)+'</b> · '+esc(info.model)+(info.device_no?' · nr urządzenia '+esc(info.device_no):'')+
    ' · '+info.doors+' drzwi'+(info.verified?'':' <span class="pill unv">profil wstępny</span>')+(err?' · <span style="color:var(--err)">'+esc(err)+'</span>':'');
  $('#saveActiveBtn').hidden=false;$('#saveActiveBtn').textContent=info.saved_id?'Zmień nazwę':'Zapisz kontroler';
  $('#disconnectBtn').hidden=false;
  $('#navCtlName').textContent=info.saved_name||info.host;
  document.title=(info.saved_name||info.host)+' · Spreest - Panel ACB';
}
function setDisconnected(){
  connected=false;lastStatus={};hideClock();
  $('#conn').className='conn';$('#dot').className='dot';
  $('#connK').textContent='Brak połączenia';$('#connName').textContent='Nie wybrano kontrolera';
  $('#connMeta').textContent='Wybierz zapisany kontroler albo wyszukaj go w sieci.';
  $('#saveActiveBtn').hidden=true;$('#disconnectBtn').hidden=true;$('#credWarn').hidden=true;$('#httpWarn').hidden=true;
  document.title='Spreest - Panel ACB';
  applyVisibility();
  goTab('find');
  loadSaved();
}

function setConnected(info){
  lastStatus=info;
  renderConn(info);
  applyVisibility();
  $('#doorVerifyNote').hidden=info.verified;
  renderStatus(info);
}

function doorList(s){const l=s.doors_list||[];
  return Array.from({length:s.doors||1},(_,i)=>l[i]||{n:i+1,name:'',delay:''});}
function doorLabel(d){return '#'+d.n+(d.name?' '+d.name:'');}
function renderDoorButtons(info){
  const multi=(info.doors||1)>1;
  const html=doorList(info).map(d=>{const name=d.name||(multi?'Drzwi #'+d.n:info.door_name)||'Drzwi';
    const delay=(d.delay||(multi?'':info.open_delay)||'').replace(/\D/g,'');
    return `<div class="doortile"><span class="dn">Drzwi #${d.n}${delay?' · otwarcie na '+esc(delay)+' s':''}</span>
      <span class="dname">${esc(name)}</span>
      <button class="btn big ok" onclick="openDoor(${d.n})">🔓 Otwórz</button></div>`;}).join('');
  if($('#doorButtons').innerHTML!==html)$('#doorButtons').innerHTML=html;
}

// --- na żywo (zdarzenia z kontrolera co sekundę) i osoby w środku ---
let liveSeq=null,liveBuf=[],liveBusy=false;
const LIVE_ICON={in:'➡️🚪',out:'🚪➡️',denied:'⛔',alarm:'🚨',device:'⚙️',warn:'⏰🚪',info:'🚪✅'};
async function livePoll(){if(liveBusy||isOffline())return;liveBusy=true;
  try{const d=await api('/api/live?after='+(liveSeq||0));
    const first=liveSeq===null;liveSeq=d.seq;
    $('#liveState').textContent=d.state==='on'?'🟢 odczyt działa':d.state==='error'?'⚠️ '+d.error:'';
    if(d.events.length){d.events.forEach(e=>e.fresh=!first);liveBuf=d.events.reverse().concat(liveBuf).slice(0,60);renderLive();
      if(!first){d.events.filter(e=>e.alert).forEach(e=>alertEvent(e,''));
        if(d.events.some(e=>e.kind==='in'||e.kind==='out')&&$('#dash').classList.contains('active'))loadPresence();}}
    else if(first)renderLive();
    if(!first)d.other_alerts.forEach(e=>alertEvent(e,e.ctrl_name));
    renderDoorsOpen(d.doors_open);
  }catch(e){}finally{liveBusy=false;}}
function durTxt(sec){sec=Math.max(0,sec|0);
  return sec<60?sec+' s':sec<3600?(sec/60|0)+' min':(sec/3600|0)+' h '+(sec%3600/60|0)+' min';}
function renderDoorsOpen(list){const el=$('#doorOpenNote'),open=list||[];
  el.hidden=!open.length;
  if(!open.length)return;
  el.className='note '+(open.some(x=>x.over)?'warn':'');
  el.innerHTML=open.map(x=>{const head=x.over?'⚠️ <b>Drzwi otwarte '+esc(durTxt(x.seconds))+'</b>':'🚪 Drzwi otwarte '+esc(durTxt(x.seconds));
    return head+' · '+esc(x.ctrl_name)+', drzwi #'+x.door+(x.door_name?' '+esc(x.door_name):'')+
      ' <span class="muted small">od '+esc(x.since.slice(11,16))+(x.over?'; ostrzeżenie po '+x.minutes+' min':'')+'</span>';}).join('<br>');}
function liveWho(e){return e.card?(esc(e.name)||'karta '+esc(e.card))+(e.dept?' <span class="muted small">· '+esc(e.dept)+'</span>':''):'';}
function renderLive(){
  if(!liveBuf.length){$('#liveList').innerHTML='<div class="muted small">Brak zdarzeń od uruchomienia panelu.</div>';return;}
  $('#liveList').innerHTML=liveBuf.map(e=>{const cls=(e.kind==='alarm'?'alarm':e.alert?'alert':'')+(e.fresh?' fresh':'');e.fresh=false;
    return `<div class="ev ${cls}"><span class="t" title="${esc(e.time)}">${esc(e.time.slice(11))}</span><span>${LIVE_ICON[e.kind]||''}</span>
      <span>${liveWho(e)}${e.card?'<br>':''}<span class="${e.alert?'warn-t':'muted'} small">${esc(e.text)}${e.blocked?' · karta zablokowana':''}</span></span>
      <span class="muted small" style="text-align:right">#${e.door}${e.door_name?' '+esc(e.door_name):''}</span></div>`;}).join('');
}
function alertEvent(e,ctrl){
  const icon=e.kind==='alarm'?'🚨 ':e.kind==='warn'?'⏰ ':'⛔ ';
  const who=(e.name||(e.card?'karta '+e.card:''));
  const msg=(ctrl?'['+ctrl+'] ':'')+icon+(who?who+' ':'')+e.text+' (drzwi #'+e.door+(e.door_name?' '+e.door_name:'')+', '+e.time.slice(11)+')';
  toast(msg,'err');
  try{if($('#liveNotif').checked&&window.Notification&&Notification.permission==='granted'&&document.hidden)
    new Notification('Spreest - Panel ACB'+(ctrl?' · '+ctrl:''),{body:msg,tag:'acb-'+e.seq});}catch(_){}
}
async function toggleBrowserNotif(c){
  if(c.checked){
    if(!window.Notification||!window.isSecureContext){c.checked=false;toast('Powiadomienia przeglądarki wymagają HTTPS albo adresu 127.0.0.1','err');return;}
    if(await Notification.requestPermission()!=='granted'){c.checked=false;toast('Przeglądarka nie zezwoliła na powiadomienia','err');return;}}
  try{localStorage.setItem('acbLiveNotif',c.checked?'1':'0');}catch(e){}}
let presBusy=false;
async function loadPresence(){if(presBusy||!connected)return;presBusy=true;
  try{const d=await api('/api/presence');
    $('#presCount').hidden=false;$('#presCount').textContent=d.count+' os.';
    if(!d.inside.length)$('#presList').innerHTML='<span class="muted small">Nikogo nie ma w środku.</span>';
    else{const groups={};d.inside.forEach(p=>(groups[p.dept||'']||=[]).push(p));
      $('#presList').innerHTML=Object.entries(groups).map(([g,l])=>`<div style="margin:0 0 10px"><div class="small muted" style="margin-bottom:4px">${g?'🏷️ '+esc(g):'Bez działu'} (${l.length})</div><div class="pres">`+
        l.map(p=>`<span class="chip" title="karta ${esc(p.card)} · ostatnie odbicie ${esc(p.last)}"><b>${esc(p.name)||'karta '+esc(p.card)}</b> <span class="muted small">od ${esc(p.since.slice(11,16))}</span></span>`).join('')+'</div></div>').join('');}
    $('#presInfo').textContent='Stan na '+d.generated.slice(11,16)+' według odbić na drzwiach '+d.doors.map(n=>'#'+n).join(', ')+' z ostatnich 16 h. Kto wyszedł bez odbicia karty, jest nadal liczony.';
  }catch(e){$('#presCount').hidden=true;$('#presList').innerHTML='<span class="muted small">'+esc(e.message)+'</span>';$('#presInfo').textContent='';}
  finally{presBusy=false;}}

function goTab(t){const b=document.querySelector('nav button[data-tab="'+t+'"]');if(!b||b.hidden)return;b.click();window.scrollTo(0,0);}

// --- status ---
// Zapytania do panelu i tak są kolejkowane po stronie serwera (jedno naraz na kontroler),
// ale nie dokładamy kolejnych odświeżeń, dopóki poprzednie się nie skończy.
let statusBusy=false;
async function loadStatus(){if(statusBusy)return;statusBusy=true;
  try{const s=await api('/api/status');renderStatus(s);renderConn(s);}
  catch(e){if(connected)renderConn(lastStatus,e.message);$('#statusGrid').innerHTML='<div class="muted">Błąd: '+esc(e.message)+'</div>';}
  finally{statusBusy=false;}
}
function renderStatus(s){
  lastStatus=s;
  $('#credWarn').hidden=!(connected&&s.default_creds&&can('admin'));
  $('#httpWarn').hidden=!connected;
  renderDoorButtons(s);
  const ev=s.events||'';const evp=/Enab/i.test(ev)?'<span class="pill on">Włączone</span>':'<span class="pill off">Wyłączone</span>';
  const groups=[['Urządzenie',[['Model',esc(s.model)+(s.verified===false?' <span class="pill unv">profil wstępny</span>':'')],['Numer urządzenia',esc(s.device_no)],['Wersja',esc(s.driver)],
      ['Liczba drzwi',String(s.doors||'')+(s.readers?'<br><span class="muted small">'+esc(s.readers)+'</span>':'')],['Liczba użytkowników',esc(s.users_total)]]],
    ['Stan',[['Zegar urządzenia','<span class="devclock">'+(clockBase?'':esc(s.clock))+'</span>'],['Status drzwi',esc(s.door_status)],
      ['Rejestr zdarzeń',evp],['Super Card',s.super_card?'🔒 zapisane: '+s.super_card:'—'],['Język',esc(s.language)],['Administrator',esc(s.manager)]]],
    ['Sieć',[['Adres IP',esc(s.ip)],['Maska',esc(s.mask)],['Brama',esc(s.gateway)]]]];
  $('#statusGrid').innerHTML=groups.map(([h,items])=>`<div class="sgrp"><h3>${h}</h3><dl class="kvl">`+
    items.map(([k,v])=>`<dt>${k}</dt><dd>${v||'—'}</dd>`).join('')+'</dl></div>').join('');
  renderClock();
}
function renderDoorParams(s){
  const inout=s.doors!==4,adm=can('admin');
  $('#doorParamsBody').innerHTML=doorList(s).map(d=>{const delay=(d.delay||'').replace(/\D/g,'');
    return `<tr><td><b>#${d.n}</b></td>
    <td><input type="text" id="doorName${d.n}" maxlength="32" style="width:100%;min-width:160px" value="${esc(d.name)}" data-orig="${esc(d.name)}" onkeydown="if(event.key==='Enter')saveDoor(${d.n})" ${adm?'':'disabled'}></td>
    <td><input type="number" id="doorDelay${d.n}" min="0" max="255" style="width:90px" value="${esc(delay)}" data-orig="${esc(delay)}" onkeydown="if(event.key==='Enter')saveDoor(${d.n})" ${adm?'':'disabled'}></td>
    <td class="muted small" style="white-space:nowrap">${inout?'wejście / wyjście':'wejście'}</td>
    <td>${inout?`<label class="small" style="white-space:nowrap"><input type="checkbox" id="track${d.n}" disabled onchange="saveTracking(${d.n},this)"> licz czas pobytu</label>`
      :`<select id="track${d.n}" disabled onchange="saveTracking(${d.n},this)" title="Każde odbicie karty na tych drzwiach panel liczy jako wejście albo wyjście">
        <option value="">nie licz</option><option value="in">➡️🚪 odbicie = wejście</option><option value="out">🚪➡️ odbicie = wyjście</option></select>`}</td>
    <td class="act">${adm?`<button class="btn sm" id="doorSave${d.n}" onclick="saveDoor(${d.n})">Zapisz</button>`:''}</td></tr>`;}).join('');
  loadTracking();
  if(!doData||$('#door').classList.contains('active'))loadDoorOpen();
}

// --- ostrzeżenie o drzwiach otwartych zbyt długo (czas liczy panel, kontroler tego nie zgłasza) ---
let doData=null,doRows='';
async function loadDoorOpen(){if(!connected||isOffline())return;
  try{doData=await api('/api/doors/open');}catch(e){return;}
  renderDoorOpen();
}
function doStateCell(x){
  if(!x.enabled)return '<span class="muted">bez pilnowania</span>';
  if(x.state==='open')return '<span class="'+(x.seconds>=x.minutes*60?'warn-t':'ok-t')+'">'+(x.seconds>=x.minutes*60?'⚠️ ':'')+
    'otwarte od '+esc(x.since.slice(11,16))+' ('+esc(durTxt(x.seconds))+')</span>';
  if(x.state==='closed')return '<span class="muted">zamknięte od '+esc(x.since.slice(11,16))+'</span>';
  return '<span class="muted">brak zdarzeń drzwi w logu</span>';
}
function renderDoorOpen(){const d=doData;if(!d)return;const adm=can('admin');
  const key=d.doors.map(x=>x.n+':'+x.name).join('|')+'/'+adm;
  if(key!==doRows){doRows=key;
    $('#doBody').innerHTML=d.doors.map(x=>`<tr><td><b>#${x.n}</b>${x.name?' '+esc(x.name):''}</td>
      <td><label class="small" style="white-space:nowrap"><input type="checkbox" id="doOn${x.n}" onchange="saveDoorOpen(${x.n})" ${adm?'':'disabled'}> ostrzegaj</label></td>
      <td style="white-space:nowrap"><input type="number" id="doMin${x.n}" min="1" max="1440" style="width:80px" onchange="saveDoorOpen(${x.n})" onkeydown="if(event.key==='Enter')saveDoorOpen(${x.n})" ${adm?'':'disabled'}> <span class="muted small">min</span></td>
      <td class="small" id="doState${x.n}">—</td></tr>`).join('');}
  d.doors.forEach(x=>{const on=$('#doOn'+x.n),mi=$('#doMin'+x.n),st=$('#doState'+x.n);
    if(on&&document.activeElement!==on)on.checked=x.enabled;
    if(mi&&document.activeElement!==mi)mi.value=x.minutes;
    if(st)st.innerHTML=doStateCell(x);});
  const on=d.doors.filter(x=>x.enabled);
  $('#doNote').className='small '+(on.length&&!d.events_on?'warn-t':'muted');
  $('#doNote').innerHTML=!on.length?'Żadne drzwi nie są pilnowane - zaznacz „ostrzegaj” przy drzwiach z czujnikiem otwarcia.'
    :(!d.events_on?'⚠️ Rejestrowanie zdarzeń jest wyłączone - kontroler nie zapisze otwarcia ani zamknięcia drzwi, więc ostrzeżenie nie zadziała. Włącz je niżej. '
      :'Pilnowane drzwi: '+on.map(x=>'#'+x.n+(x.name?' '+esc(x.name):'')+' ('+x.minutes+' min)').join(', ')+'. ')+
      (d.notify_on?'Powiadomienia e-mail/Telegram/webhook: <b>włączone</b> dla tej reguły.'
        :'Powiadomienia dla tej reguły są wyłączone w zakładce „Powiadomienia” - ostrzeżenie pokaże się tylko w panelu.');
  $('#doHist').innerHTML=d.history.length?d.history.map(h=>`<tr><td>#${h.door}${h.door_name?' '+esc(h.door_name):''}</td>
    <td style="white-space:nowrap">${esc(h.from)}</td><td style="white-space:nowrap">${esc(h.to)}</td>
    <td class="warn-t" style="white-space:nowrap">${esc(h.text)}</td></tr>`).join('')
    :'<tr><td colspan="4" class="muted">Brak długich otwarcień w zapisie panelu.</td></tr>';
  $('#doHistNote').textContent='Zakończone otwarcia z ostatnich '+d.history_days+' dni dłuższe niż ustawiony czas '+
    '(drzwi bez pilnowania liczą się od '+d.default_minutes+' min). Źródło: zdarzenia zapisane przez panel i kopia logu przejść.';
}
async function saveDoorOpen(n){const on=$('#doOn'+n),mi=$('#doMin'+n);
  on.disabled=mi.disabled=true;
  try{doData=await api('/api/doors/open',form({door:n,enabled:on.checked?'1':'0',minutes:mi.value}));
    renderDoorOpen();toast(doData.msg,'ok');}
  catch(e){toast('Błąd: '+e.message,'err');loadDoorOpen();}
  finally{if(can('admin')){on.disabled=false;mi.disabled=false;}}
}
// --- godziny wejścia działów (tryb drzwi w liście zadań + PIN-y kart przełączane przez panel) ---
let ehData=null;
const EH_DAYS=['Pn','Wt','Śr','Cz','Pt','So','Nd'];
const EH_MODES={hours:'w godzinach',always:'o każdej porze',none:'brak wejścia'};
async function loadEntryHours(){
  try{ehData=await api('/api/entryhours');renderEntryHours();}
  catch(e){$('#ehBody').innerHTML='<tr><td colspan="7" class="muted">Błąd: '+esc(e.message)+'</td></tr>';}
}
function ehOvernight(g){return g.mode==='hours'&&g.end<=g.start?(g.end===g.start?'cała doba':'do następnego dnia'):'';}
function renderEntryHours(){const d=ehData;
  $('#ehDoors').innerHTML=d.doors.map(x=>`<label class="chip" style="padding:7px 14px;cursor:pointer;white-space:nowrap"><input type="checkbox" class="eh-door" data-door="${x.n}" ${x.enabled?'checked':''} onchange="ehDirty(this)"> ${esc(doorLabel(x))}</label>`).join('');
  $('#ehBody').innerHTML=d.groups.map(g=>{const off=g.mode==='hours'?'':'disabled';
    const who=g.key==='nodept'?`<span title="${esc((g.people||[]).join(', '))}">${esc(g.name)}</span>`:'🏷️ '+esc(g.name);
    return `<tr data-group="${esc(g.key)}"><td><b>${who}</b></td><td class="muted">${g.cards}</td>
    <td><select class="eh-mode" onchange="ehDirty(this)">${Object.entries(EH_MODES).map(([k,v])=>`<option value="${k}" ${g.mode===k?'selected':''}>${v}</option>`).join('')}</select></td>
    <td><input type="time" class="eh-start" value="${esc(g.start)}" oninput="ehDirty(this)" ${off}></td>
    <td style="white-space:nowrap"><input type="time" class="eh-end" value="${esc(g.end)}" oninput="ehDirty(this)" ${off}> <span class="small muted eh-night">${ehOvernight(g)}</span></td>
    <td style="white-space:nowrap">${EH_DAYS.map((n,i)=>`<label class="small" style="margin-right:6px"><input type="checkbox" class="eh-day" ${g.days[i]==='1'?'checked':''} onchange="ehDirty(this)" ${off}>${n}</label>`).join('')}</td>
    <td class="small" style="white-space:nowrap">${!d.restricted?'<span class="muted" title="Żadne drzwi nie mają zapisanego ograniczenia">—</span>':g.now?'<span class="ok-t">🟢 wchodzi</span>':'<span class="muted">⛔ nie</span>'}</td></tr>`;}).join('');
  renderEhHolidays(d.holidays||[]);
  const ht=d.holiday_today;$('#ehHolToday').innerHTML=ht&&d.restricted?'<span class="warn-t">Dziś: '+esc(ht.name||'wyjątek')+' ('+(ht.mode==='closed'?'brak wejścia':ht.start+'–'+ht.end)+')</span>':'';
  if(!can('admin'))document.querySelectorAll('#hours input,#hours select').forEach(i=>i.disabled=true);
  renderEhState(false);renderEhWatch();renderEhPlan();
  const stale=$('#ehOfflineStale');stale.hidden=!d.offline_stale;
  if(d.offline_stale)stale.innerHTML='<b>⚠️ Na kontrolerze jest zapisany harmonogram na kilka zmian</b>, a panel działa w trybie offline - '
    +'nikt nie przełącza teraz godzin. Karty zostały w stanie z chwili, gdy ostatnio pracował panel online. '
    +'Ustaw wszystkim działom z kartami te same godziny (jedna zmiana) albo uruchom panel w trybie online.';
}
function ehHolRow(h){const past=h.to<isoDay(0),off=h.mode==='hours'?'':'disabled';
  return `<tr class="eh-hol${past?' past':''}"><td><input type="date" class="h-from" value="${esc(h.from)}" onchange="ehDirty(this)"></td>
    <td><input type="date" class="h-to" value="${esc(h.to)}" onchange="ehDirty(this)"></td>
    <td><input type="text" class="h-name" maxlength="40" value="${esc(h.name)}" oninput="ehDirty(this)" style="min-width:140px"></td>
    <td><select class="h-mode" onchange="ehHolMode(this)"><option value="closed" ${h.mode==='closed'?'selected':''}>brak wejścia</option><option value="hours" ${h.mode==='hours'?'selected':''}>skrócone godziny</option></select></td>
    <td><input type="time" class="h-start" value="${esc(h.start||'08:00')}" oninput="ehDirty(this)" ${off}></td>
    <td><input type="time" class="h-end" value="${esc(h.end||'12:00')}" oninput="ehDirty(this)" ${off}></td>
    <td class="act"><button class="iconbtn del" onclick="this.closest('tr').remove();ehHolEmpty();ehDirty(this)">Usuń</button></td></tr>`;}
function renderEhHolidays(list){$('#ehHol').innerHTML=list.map(ehHolRow).join('');ehHolEmpty();}
function ehHolEmpty(){if(!document.querySelector('#ehHol tr.eh-hol'))$('#ehHol').innerHTML='<tr class="eh-none"><td colspan="7" class="muted">Brak wyjątków.</td></tr>';}
function ehHolMode(sel){const tr=sel.closest('tr');tr.querySelectorAll('.h-start,.h-end').forEach(i=>i.disabled=sel.value!=='hours');ehDirty(sel);}
function ehHolAppend(h){const n=document.querySelector('#ehHol tr.eh-none');if(n)n.remove();$('#ehHol').insertAdjacentHTML('beforeend',ehHolRow(h));}
function ehAddHoliday(){const t=isoDay(1);ehHolAppend({from:t,to:t,name:'',mode:'closed',start:'08:00',end:'12:00'});
  const rows=document.querySelectorAll('#ehHol tr.eh-hol');rows[rows.length-1].querySelector('.h-name').focus();renderEhState(true);}
async function ehAddPl(b){b.disabled=true;
  try{const d=await api('/api/holidays/pl?year='+$('#ehPlYear').value);
    const have=new Set([...document.querySelectorAll('#ehHol tr.eh-hol')].map(tr=>tr.querySelector('.h-from').value));
    const add=d.holidays.filter(h=>!have.has(h.date)&&h.date>=isoDay(0));
    add.forEach(h=>ehHolAppend({from:h.date,to:h.date,name:h.name,mode:'closed'}));
    toast(add.length?'Dodano świąt: '+add.length+' - zapisz na kontrolerze':'Święta z tego roku są już na liście (minione pominięto)',add.length?'ok':'');
    if(add.length)renderEhState(true);}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}
function ehDropPast(){let n=0;document.querySelectorAll('#ehHol tr.eh-hol').forEach(tr=>{if(tr.querySelector('.h-to').value<isoDay(0)){tr.remove();n++;}});
  ehHolEmpty();if(n){renderEhState(true);toast('Usunięto minionych: '+n+' - zapisz na kontrolerze','ok');}else toast('Brak minionych wyjątków','');}
function ehPlan(cfg){
  if(!Object.values(cfg.doors).some(Boolean))return {kind:'off'};
  const wins={},none=[];
  for(const g of ehData.groups){const v=cfg.groups[g.key];if(!g.cards||v.mode==='always')continue;
    if(v.mode==='none')none.push(g.name);
    else(wins[v.start+'–'+v.end+' '+EH_DAYS.filter((_,i)=>v.days[i]==='1').join(' ')]||=[]).push(g.name);}
  const w=Object.keys(wins);
  return none.length||w.length>1?{kind:'multi',wins,none}:{kind:'single',win:w[0]};
}
function renderEhPlan(){let cfg;try{cfg=ehCollect();}catch(e){return;}
  const p=ehPlan(cfg),el=$('#ehPlan');el.className='note '+({single:'ok',multi:'warn'}[p.kind]||'');
  if(p.kind==='off'){el.innerHTML='<span class="muted">Żadne drzwi nie mają ograniczenia - panel nie musi być podłączony.</span>';return;}
  if(p.kind==='single'){el.innerHTML='<span class="ok-t">✅ Teraz: jedna zmiana'+(p.win?' ('+esc(p.win)+')':' (wszyscy o każdej porze)')+' - panel nie musi być podłączony.</span>';return;}
  const why=Object.entries(p.wins).map(([w,n])=>esc(n.join(', '))+': '+esc(w)).concat(p.none.length?[esc(p.none.join(', '))+': brak wejścia']:[]);
  el.innerHTML='<span class="warn-t">⚠️ Teraz: więcej niż jedna zmiana - panel musi być stale podłączony.</span> <span class="muted">('+why.join('; ')+')</span>';
}
function renderEhWatch(){const d=ehData;
  const w=d.watch||{},cls={active:'ok-t',error:'warn-t'}[w.state]||'muted';
  $('#ehWatch').textContent=({active:'🟢 ',error:'⚠️ '}[w.state]||'⚪ ')+'Przełączanie PIN-ów: '+(w.msg||'')+' (zegar kontrolera '+d.clock+')';$('#ehWatch').className='small '+cls;
  const p=d.pins;
  $('#ehPins').innerHTML=!p||p.skipped?'':p.error?'<span class="warn-t">⚠️ PIN-y w kontrolerze nie zostały ustawione: '+esc(p.error)+'</span>'
    :'<span class="ok-t">✅ PIN 0 w kontrolerze: kart '+p.free+' z '+p.cards+'</span> <span class="muted">(sprawdzono '+esc(p.at.slice(11,16))+(p.changed.length?', zmieniono: '+p.changed.map(x=>esc(x.name||x.card)+' → '+x.pin).join(', '):'')+')</span>'
    +(d.people_checked?'':' <span class="warn-t">⚠️ nie udało się odczytać listy kart z kontrolera - liczby kart mogą obejmować karty usunięte</span>');
  $('#ehPasses').innerHTML=d.passes.length?'Ostatnio wpuszczeni przez panel po odmowie kontrolera: '+d.passes.map(p=>esc(p.time.slice(5,16))+' '+esc(p.name||('karta '+p.card))+' #'+p.door+(/^(udp|www)$/.test(p.result)?'':' <span class="warn-t">('+esc(p.result)+')</span>')).join(' · '):'';
}
function renderEhState(dirty){const d=ehData;
  let t,c;
  if(dirty){t='Niezapisane zmiany';c='warn-t';}
  else if(d.error){t='⚠️ Nie zapisano na kontrolerze: '+d.error;c='warn-t';}
  else if(d.pending){t='⚠️ Konfiguracja nie została zapisana na kontrolerze';c='warn-t';}
  else if(d.applied_at){t='✅ Zapisane na kontrolerze '+d.applied_at;c='ok-t';}
  else{t='Brak ograniczeń zapisanych z tego panelu';c='muted';}
  $('#ehState').textContent=t;$('#ehState').className='small '+c;
}
function ehRow(tr){return {mode:tr.querySelector('.eh-mode').value,start:tr.querySelector('.eh-start').value||'08:00',
  end:tr.querySelector('.eh-end').value||'16:00',days:[...tr.querySelectorAll('.eh-day')].map(c=>c.checked?'1':'0').join('')};}
function ehDirty(el){const tr=el.closest('tr[data-group]');
  if(tr){const g=ehRow(tr);
    tr.querySelectorAll('.eh-start,.eh-end,.eh-day').forEach(i=>i.disabled=g.mode!=='hours');
    tr.querySelector('.eh-night').textContent=ehOvernight(g);}
  renderEhState(true);renderEhPlan();}
function ehCollect(){const cfg={doors:{},groups:{}};
  document.querySelectorAll('#ehDoors .eh-door').forEach(c=>cfg.doors[c.dataset.door]=c.checked);
  for(const tr of document.querySelectorAll('#ehBody tr[data-group]')){const g=ehRow(tr);
    if(g.mode==='hours'&&!g.days.includes('1'))throw new Error(tr.querySelector('td').textContent.trim()+': zaznacz dni z wejściem albo wybierz „brak wejścia”');
    cfg.groups[tr.dataset.group]=g;}
  cfg.holidays=[...document.querySelectorAll('#ehHol tr.eh-hol')].map(tr=>{const h={from:tr.querySelector('.h-from').value,to:tr.querySelector('.h-to').value||tr.querySelector('.h-from').value,
    name:tr.querySelector('.h-name').value.trim(),mode:tr.querySelector('.h-mode').value,start:tr.querySelector('.h-start').value||'08:00',end:tr.querySelector('.h-end').value||'12:00'};
    if(!h.from)throw new Error('Wyjątek „'+(h.name||'bez nazwy')+'”: podaj datę');if(h.to<h.from)throw new Error('Wyjątek „'+(h.name||h.from)+'”: data „do” przed „od”');return h;});
  return cfg;}
async function saveEntryHours(b){
  let cfg;try{cfg=ehCollect();}catch(e){toast(e.message,'err');return;}
  const doors=ehData.doors.filter(x=>cfg.doors[x.n]);
  const summary=doors.length?'Ograniczenie na drzwiach: '+doors.map(x=>doorLabel(x)).join(', ')+'\n\n'+ehData.groups.map(g=>{const v=cfg.groups[g.key];
      return g.name+': '+(v.mode==='hours'?v.start+'–'+v.end+(ehOvernight(v)?' ('+ehOvernight(v)+')':'')+', '+EH_DAYS.filter((_,i)=>v.days[i]==='1').join(' '):EH_MODES[v.mode]);}).join('\n')
    :'bez ograniczeń na wszystkich drzwiach';
  const hol=cfg.holidays.filter(h=>h.to>=isoDay(0));
  const holTxt=doors.length&&hol.length?'\n\nWyjątki w kalendarzu ('+hol.length+'): '+hol.slice(0,6).map(h=>h.from+(h.to!==h.from?'–'+h.to:'')+' '+(h.name||'')+(h.mode==='hours'?' '+h.start+'–'+h.end:'')).join('; ')+(hol.length>6?'; ...':''):'';
  const plan=ehPlan(cfg).kind;
  if(!confirm('Zapisać godziny wejścia na kontrolerze „'+ctrlLabel(lastStatus)+'”?\n\n'+summary+holTxt+'\n\nZapis zastępuje całą listę zadań kontrolera.'
    +(plan==='multi'?'\n\nWIĘCEJ NIŻ JEDNA ZMIANA: panel musi być stale podłączony do kontrolera.':plan==='single'?'\n\nJedna zmiana: po zapisie panel nie musi być podłączony.':'')))return;
  b.disabled=true;$('#ehInfo').innerHTML='<span class="spin"></span> Zapisywanie na kontrolerze...';
  try{ehData=await api('/api/entryhours',form({config:JSON.stringify(cfg)}));renderEntryHours();
    $('#ehInfo').textContent=ehData.msg;$('#ehInfo').className='small ok-t';toast('Zapisano godziny wejścia','ok');}
  catch(e){$('#ehInfo').textContent='Błąd: '+e.message;$('#ehInfo').className='small warn-t';toast('Błąd: '+e.message,'err');
    try{const st=await api('/api/entryhours');ehData=st;renderEhState(false);renderEhWatch();}catch(_){}}
  finally{b.disabled=false;}
}
// --- analiza czasu pracy: które drzwi liczą pobyt (zapisywane w panelu) ---
let tracking=null;
async function loadTracking(){
  try{tracking=await api('/api/tracking');}catch(e){$('#trackNote').textContent='Błąd: '+e.message;return;}
  renderTracking();
}
function renderTracking(){const t=tracking;if(!t)return;
  const roles=t.mode==='roles';
  t.doors.forEach(d=>{const c=$('#track'+d.n);if(!c)return;
    if(c.tagName==='SELECT')c.value=d.role||'';else c.checked=d.enabled;c.disabled=!t.supported||!can('admin');});
  const on=t.doors.filter(d=>d.enabled),ready=t.supported&&t.ready!==false&&on.length>0;
  const list=r=>on.filter(d=>d.role===r).map(d=>doorLabel(d)).join(', ')||'—';
  $('#trackNote').className='small '+(ready?'muted':'warn-t');
  $('#trackNote').textContent=!t.supported?'Analiza czasu pracy niedostępna: '+t.reason
    :roles?(ready?'Czas pracy liczony z par drzwi - wejście: '+list('in')+'; wyjście: '+list('out')+'. Raport jest w zakładce „Czas pracy”.'
        :'Przy drzwiach jest tylko czytnik wejścia, więc wejście i wyjście to różne drzwi: wskaż, które drzwi są wejściem, a które wyjściem (co najmniej jedne każdego rodzaju).')
      +' Godzin wejścia nie ustawiaj na drzwiach wyjścia - zablokowałyby wyjście.'
    :on.length?'Czas pracy liczony na drzwiach: '+on.map(d=>doorLabel(d)).join(', ')+'. Raport jest w zakładce „Czas pracy”.'
    :'Zaznacz drzwi, na których pracownicy odbijają kartę przy wejściu i wyjściu - raport pojawi się w zakładce „Czas pracy”.';
  const sel=$('#wtPlace'),cur=sel.value;
  sel.innerHTML=roles?(ready?'<option value="all">Wejście '+esc(list('in'))+' · wyjście '+esc(list('out'))+'</option>':'')
    :(on.length>1?'<option value="all">Wszystkie zaznaczone drzwi razem</option>':'')+
    on.map(d=>`<option value="${d.n}">Drzwi ${esc(doorLabel(d))}</option>`).join('');
  if([...sel.options].some(o=>o.value===cur))sel.value=cur;
  sel.disabled=!ready;$('#wtBtn').disabled=$('#wtCsvBtn').disabled=$('#wtPrintBtn').disabled=!ready;
  if(!t.supported)$('#wtInfo').innerHTML='<span class="warn-t">Niedostępne dla tego kontrolera: '+esc(t.reason)+'</span>';
  else if(!ready)$('#wtInfo').innerHTML=(roles?esc(t.reason):'Żadne drzwi nie liczą czasu pracy.')+' <a href="#" onclick="goTab(\'door\');return false">Ustaw to w zakładce „Drzwi”</a>.';
  else if(!$('#wtBody').innerHTML&&!wtBusy)$('#wtInfo').textContent='Wybierz okres i filtry - raport przeliczy się sam.';
}
async function saveTracking(n,c){c.disabled=true;const sel=c.tagName==='SELECT';
  try{tracking=await api('/api/tracking',form(sel?{door:n,role:c.value}:{door:n,enabled:c.checked?'1':'0'}));
    toast('Drzwi #'+n+': '+(sel?{'in':'drzwi wejścia','out':'drzwi wyjścia','':'nie liczą czasu pracy'}[c.value]
      :'analiza czasu pracy '+(c.checked?'włączona':'wyłączona')),'ok');}
  catch(e){if(!sel)c.checked=!c.checked;toast('Błąd: '+e.message,'err');}
  finally{renderTracking();}}
function fillForms(){const s=lastStatus;
  renderDoorParams(s);
  if($('#events'))$('#events').value=/Enab/i.test(s.events||'')?'1':'2';
  if($('#lang'))$('#lang').value=/chin/i.test(s.language||'')?'chinese':'english';
  if($('#netIp'))$('#netIp').value=s.ip||'';
  if($('#netGw'))$('#netGw').value=s.gateway||'';
  if($('#netMask'))$('#netMask').value=s.mask||'';
  const dl=s.default_creds&&s.default_login;
  $('#oldName').value=dl?dl.user:(s.manager||'');
  $('#oldPwd').value=dl?dl.pwd:'';
  $('#admDefaultNote').hidden=!dl;
}

// --- użytkownicy ---
// --- działy (zapisywane w panelu, wspólne dla kontrolerów; pracownik = numer karty) ---
let depts=[],usersCache=[],people=[];
function deptOptions(cur,{all,none}={}){
  return (all?`<option value="">${all}</option>`:'')+(none?`<option value="none">${none}</option>`:'')+
    depts.map(d=>`<option value="${d.id}" ${String(d.id)===String(cur)?'selected':''}>${esc(d.name)}</option>`).join('');
}
function setOptions(sel,html){const cur=sel.value;sel.innerHTML=html;if([...sel.options].some(o=>o.value===cur))sel.value=cur;}
function renderDepts(){
  $('#deptList').innerHTML=depts.length?depts.map(d=>`<span class="chip">🏷️ <b>${esc(d.name)}</b>
    <span class="muted small">${d.people} os.</span>
    <button class="iconbtn" data-id="${d.id}" data-name="${esc(d.name)}" onclick="renameDept(this.dataset)">Zmień nazwę</button>
    <button class="iconbtn del" data-id="${d.id}" data-name="${esc(d.name)}" onclick="deleteDept(this.dataset)">Usuń</button></span>`).join('')
    :'<span class="muted small">Brak działów - dodaj pierwszy, np. „Magazyn” albo „Biuro”.</span>';
  setOptions($('#deptFilter'),deptOptions('',{all:'Wszystkie działy',none:'Bez działu'}));
  setOptions($('#fDept'),deptOptions('',{all:'Wszystkie działy',none:'Bez działu'}));
  setOptions($('#wDept'),deptOptions('',{all:'Wszystkie działy',none:'Bez działu'}));
  setOptions($('#bulkDept'),deptOptions('',{all:'— bez działu —'}));
  setOptions($('#selDept'),deptOptions('',{all:'— bez działu —'}));
}
async function addDept(){const name=$('#newDept').value.trim();if(!name){toast('Podaj nazwę działu','err');return;}
  try{const d=await api('/api/departments/add',form({name}));depts=d.departments;$('#newDept').value='';
    renderDepts();renderUsers();toast('Dodano dział „'+name+'”','ok');}catch(e){toast('Błąd: '+e.message,'err');}}
async function renameDept({id,name}){const r=await nameDialog('Zmień nazwę działu','',name,false,'Nazwa działu');if(!r||!r.name||r.name===name)return;
  try{const d=await api('/api/departments/rename',form({id,name:r.name}));depts=d.departments;
    usersCache.forEach(u=>{if(String(u.dept_id)===id)u.dept=r.name;});renderDepts();renderUsers();toast('Zmieniono nazwę działu','ok');}
  catch(e){toast('Błąd: '+e.message,'err');}}
async function deleteDept({id,name}){if(!confirm('Usunąć dział „'+name+'”?\nPracownicy zostaną bez działu - karty na kontrolerze się nie zmienią.'))return;
  try{const d=await api('/api/departments/delete',form({id}));depts=d.departments;
    usersCache.forEach(u=>{if(String(u.dept_id)===id){u.dept_id=null;u.dept=null;}});renderDepts();renderUsers();toast('Usunięto dział','ok');}
  catch(e){toast('Błąd: '+e.message,'err');}}
async function assignDept(sel){const u=usersCache.find(x=>x.user_id===sel.dataset.id);if(!u)return;sel.disabled=true;
  try{const d=await api('/api/people/assign',form({card:u.card,name:u.name,dept_id:sel.value}));
    depts=d.departments;u.dept_id=sel.value?+sel.value:null;u.dept=u.dept_id?(depts.find(x=>x.id===u.dept_id)||{}).name:null;
    renderDepts();renderUsers();toast((u.name||'Karta '+u.card)+': '+(u.dept||'bez działu')
      +(d.pins?' · PIN w kontrolerze: '+d.pins.map(x=>x.pin).join(', '):''),'ok');
    if(d.warning)toast(d.warning,'err');}
  catch(e){toast('Błąd: '+e.message,'err');sel.disabled=false;}}

// --- zaznaczanie wielu osób i przypisanie ich do działu jednym kliknięciem ---
// Zaznaczenie trzyma numery kart (a nie wierszy), więc przeżywa przerysowanie tabeli po zmianie filtra.
let selCards=new Set();
function visibleCards(){return [...document.querySelectorAll('#usersBody input.usel')].map(c=>c.dataset.card);}
function renderSel(){
  const n=selCards.size,vis=visibleCards();
  $('#selBar').hidden=!n||!can('operator');
  $('#selCount').textContent=n?'Zaznaczono: '+n+' os.':'';
  const all=$('#selAll');if(all){const on=vis.length&&vis.every(c=>selCards.has(c));
    all.checked=!!on;all.indeterminate=!on&&vis.some(c=>selCards.has(c));}
}
function toggleSel(cb){cb.checked?selCards.add(cb.dataset.card):selCards.delete(cb.dataset.card);renderSel();}
function selectAllUsers(cb){const vis=visibleCards();
  vis.forEach(c=>cb.checked?selCards.add(c):selCards.delete(c));
  document.querySelectorAll('#usersBody input.usel').forEach(x=>x.checked=cb.checked);renderSel();}
function clearSel(){selCards.clear();document.querySelectorAll('#usersBody input.usel').forEach(x=>x.checked=false);renderSel();}
async function assignSelected(b){const cards=[...selCards];if(!cards.length)return;
  const id=$('#selDept').value,name=id?(depts.find(x=>String(x.id)===String(id))||{}).name:'';
  if(!confirm('Przypisać '+cards.length+' os. '+(id?'do działu „'+name+'”?':'do „bez działu”?')))return;
  b.disabled=true;
  try{const d=await api('/api/people/assign-bulk',form({cards:cards.join(','),dept_id:id}));
    depts=d.departments;
    usersCache.forEach(u=>{if(selCards.has(u.card)){u.dept_id=id?+id:null;u.dept=id?name:null;}});
    clearSel();renderDepts();renderUsers();loadPeople();
    toast(d.msg+(d.pins?' · PIN-y w kontrolerze: '+d.pins.length:''),'ok');
    if(d.warning)toast(d.warning,'err');}
  catch(e){toast('Błąd: '+e.message,'err');}
  finally{b.disabled=false;}}

// --- użytkownicy ---
let usersBusy=false;
function ucols(){return can('operator')?7:6;}
async function loadUsers(){if(usersBusy)return;usersBusy=true;
  const q=encodeURIComponent($('#search').value.trim());
  if(!usersCache.length)$('#usersBody').innerHTML='<tr><td colspan="'+ucols()+'" class="muted"><span class="spin"></span> Odczyt użytkowników z kontrolera...</td></tr>';
  try{const d=await api('/api/users?q='+q);usersCache=d.users;usersUdp=d.udp;depts=d.departments;
    selCards=new Set([...selCards].filter(c=>usersCache.some(u=>u.card===c)));renderDepts();renderUsers();
    const n=$('#usersNote');n.hidden=d.udp&&d.complete!==false;
    n.textContent=!d.udp?'Kanał UDP 60000 kontrolera nie odpowiada - ważność i blokady kart są niedostępne, a lista może obejmować tylko 20 pierwszych użytkowników.'
      :d.complete===false?'Nie udało się odczytać wszystkich użytkowników ze strony kontrolera ('+d.users.length+' z '+d.total+').':'';}
  catch(e){usersCache=[];$('#usersBody').innerHTML='<tr><td colspan="'+ucols()+'" class="muted">'+esc(e.message)+'</td></tr>';}
  finally{usersBusy=false;}
}
function validityCell(u){
  if(u.validity==='blocked')return `<span class="pill off" title="${esc(u.block?('zablokował '+u.block.login+' '+u.block.time+(u.block.reason?' - '+u.block.reason:'')):'brak dostępu do wszystkich drzwi')}">⛔ zablokowana</span>`+(u.block&&u.block.reason?'<br><span class="muted small">'+esc(u.block.reason)+'</span>':'');
  if(u.validity==='expired')return `<span class="pill off">wygasła ${esc(u.valid_to)}</span>`;
  if(u.validity==='future')return `<span class="pill unv">od ${esc(u.valid_from)}</span>`;
  if(u.validity==='expiring')return `<span class="pill warn">wygasa ${esc(u.valid_to)}</span>`;
  if(u.validity==='ok')return u.temporary?`<span class="small">do ${esc(u.valid_to)}</span>`:'<span class="muted small">bez terminu</span>';
  return '<span class="muted small">—</span>';
}
let usersUdp=true;
function renderUsers(){
  const f=$('#deptFilter').value;
  const list=usersCache.filter(u=>!f||(f==='none'?!u.dept_id:String(u.dept_id)===f));
  $('#usersCount').textContent=usersCache.length?(list.length===usersCache.length?list.length+' os.':list.length+' z '+usersCache.length+' os.'):'';
  if(!list.length){$('#usersBody').innerHTML='<tr><td colspan="'+ucols()+'" class="muted">'+(usersCache.length?'Brak użytkowników w tym dziale':'Brak użytkowników')+'</td></tr>';renderSel();return;}
  // grupy: działy alfabetycznie, na końcu osoby bez działu
  const groups=[...depts.map(d=>({id:d.id,name:'🏷️ '+d.name})),{id:null,name:'Bez działu'}].map(g=>({...g,users:list.filter(u=>
    g.id===null?!depts.some(d=>d.id===u.dept_id):u.dept_id===g.id)})).filter(g=>g.users.length);
  const op=can('operator');
  const row=u=>`<tr>${op?`<td><input type="checkbox" class="usel" data-card="${esc(u.card)}" ${selCards.has(u.card)?'checked':''} onchange="toggleSel(this)"></td>`:''}<td class="muted">${esc(u.user_id)}</td><td>${cardCell(u.card)}</td><td><b>${esc(u.name)}</b></td>
    <td>${op?`<select data-id="${esc(u.user_id)}" onchange="assignDept(this)" style="padding:5px 8px">${deptOptions(u.dept_id,{all:'— bez działu —'})}</select>`:esc(u.dept||'—')}</td>
    <td>${validityCell(u)}</td>
    <td class="act">${op?`
    <button class="iconbtn" data-id="${esc(u.user_id)}" onclick="editUser(this.dataset.id)">Edytuj / dostęp</button>
    ${usersUdp?`<button class="iconbtn" data-id="${esc(u.user_id)}" onclick="changeCard(this.dataset.id)" title="Nowy numer karty dla tej osoby - stara karta straci dostęp">🔁 Zmień kartę</button>`:''}
    ${usersUdp?(u.blocked?`<button class="iconbtn" data-card="${esc(u.card)}" onclick="unblockCard(this.dataset.card)">Odblokuj</button>`
      :`<button class="iconbtn del" data-card="${esc(u.card)}" data-label="${esc(u.name||u.card)}" onclick="blockCard(this.dataset.card,this.dataset.label)">Zablokuj</button>`):''}
    <button class="iconbtn del" data-id="${esc(u.user_id)}" data-label="${esc(u.name||u.card)}" onclick="delUser(this.dataset.id,this.dataset.label)">Usuń</button>`:''}</td></tr>`;
  $('#usersBody').innerHTML=groups.map(g=>(depts.length?`<tr class="grp"><td colspan="${ucols()}">${esc(g.name)} <span class="muted small">(${g.users.length})</span></td></tr>`:'')+g.users.map(row).join('')).join('');
  renderSel();
}
// -- numer nadrukowany na karcie a numer widziany przez kontroler (Wiegand-26) --
// Czytnik przesyła kontrolerowi tylko 24 bity numeru karty: 8 bitów kodu obiektu + 16 bitów numeru.
// Kontroler skleja je z powrotem dziesiętnie (FC * 100000 + CN), więc karta z nadrukiem 99999
// trafia do logu jako 134463. BigInt, bo pole przyjmuje do 19 cyfr - Number gubi dokładność powyżej 2^53.
const WG_CN_MAX=65535n,WG_FC_MAX=255n,WG_SPAN=16777216n;
function wgDigits(v){const d=String(v||'').replace(/\D/g,'').replace(/^0+(?=\d)/,'');return /^\d+$/.test(d)&&d.length<=19?d:null;}
function wgRead(v){const d=wgDigits(v);if(d===null)return null;const n=BigInt(d)%WG_SPAN;return (n/65536n)*100000n+(n%65536n);}
function wgCard(v){const d=wgDigits(v);if(d===null)return null;const n=BigInt(d),fc=n/100000n,cn=n%100000n;
  return (cn>WG_CN_MAX||fc>WG_FC_MAX)?null:fc*65536n+cn;}
function cardWarn(v,masked){const d=wgDigits(v);if(d===null||BigInt(d)<=WG_CN_MAX)return '';
  if(masked)return 'Numer jest większy niż 65535 - sprawdź w „Numer na karcie a numer w kontrolerze” (zakładka „Pracownicy i karty”), czy kontroler widzi tę kartę pod tym samym numerem.';
  const read=wgRead(d);
  if(read===0n)return '⛔ Numer '+d+' jest wielokrotnością 16777216 - czytnik widzi taką kartę jako numer 0 i kontroler w ogóle jej nie rejestruje.';
  if(wgCard(d)===null)return '⛔ Kontroler nigdy nie zgłosi numeru '+d+'. Jeśli to numer nadrukowany na karcie, wpisz '+read+'.';
  return 'Jeśli '+d+' to numer nadrukowany na karcie, kontroler zobaczy ją jako '+read+' - wpisz ten numer. Numer wzięty z logu przejść albo z listy kart jest poprawny taki, jaki jest.';}
function cardCell(card){const d=wgDigits(card);if(d===null||BigInt(d)<=WG_CN_MAX)return esc(card);
  const c=wgCard(d);return c===null?esc(card)
    :`<span class="wgc" title="Na karcie nadrukowany numer ${c} - czytnik zgłasza ją kontrolerowi jako ${d}">${esc(card)}</span>`;}
function wgCalc(from,p='wg'){const a=$('#'+p+'Card'),b=$('#'+p+'Ctrl'),m=$('#'+p+'Msg'),src=from==='card'?a:b,dst=from==='card'?b:a;
  if(!src.value.trim()){a.value=b.value='';m.textContent='';return;}
  const d=wgDigits(src.value);
  if(d===null){dst.value='';m.textContent='Wpisz sam numer, bez liter i spacji (do 19 cyfr).';return;}
  if(from==='card'){const r=wgRead(d);dst.value=String(r);
    m.textContent=r===0n?'Ta karta jest dla kontrolera numerem 0 - nie da się jej użyć.'
      :(BigInt(d)<=WG_CN_MAX?'Numer do 65535 kontroler widzi bez zmian.':'Kartę z takim nadrukiem wpisz w panelu jako '+r+'.');
  }else{const c=wgCard(d);dst.value=c===null?'':String(c);
    m.textContent=c===null?'Takiego numeru czytnik nigdy nie zgłosi - pięć ostatnich cyfr może sięgać 65535, a początek 255.'
      :(BigInt(d)<=WG_CN_MAX?'Numer do 65535 jest taki sam po obu stronach.':'Na takiej karcie nadrukowany jest numer '+c+'.');}}
function cardHint(input='#newCard',hint='#cardHint',masked=false){const v=$(input).value.trim(),h=$(hint);h.className='small warn-t';
  const zeros=/^0+\d/.test(v)?'Numer zaczyna sie od zer - wpisz go bez nich'+(masked?'.':': '+v.replace(/^0+/,'')):'';
  const txt=[zeros,cardWarn(v,masked)].filter(Boolean).join(' ');
  h.hidden=!txt;h.textContent=txt;}
async function addCard(){const card=$('#newCard').value.trim(),name=$('#newName').value.trim(),vt=$('#newValidTo').value;
  if(!card){toast('Podaj numer karty','err');return;}
  // ta sama nazwa co u osoby z inną kartą - zapytaj, czy to wymiana karty
  let pick=null;
  if(name){let c=[];try{c=(await api('/api/cards/candidates?'+new URLSearchParams({name,card}))).candidates||[];}catch(e){}
    if(c.length){pick=await replAsk(card,name,c);if(pick===undefined)return;}}
  if(pick&&pick.on_ctrl){
    try{const r=await api('/api/cards/replace',form({user_id:'',old:pick.card,new:card}));toast(r.msg,'ok');
      $('#newCard').value='';$('#newName').value='';$('#newValidTo').value='';
      const h=$('#cardHint');h.hidden=!r.warning;h.textContent=r.warning||'';if(r.warning)toast(r.warning,'err');
      loadUsers();loadPeople();}catch(e){toast('Błąd: '+e.message,'err');loadUsers();}
    return;}
  try{const r=await api('/api/addcard',form({card,name,valid_to:vt}));toast(r.msg||('Dodano kartę '+card),'ok');
    if(pick){try{const l=await api('/api/cards/link',form({old:pick.card,new:card}));toast(l.msg,'ok');}
      catch(e){toast('Dodano kartę, ale nie połączono jej z kartą '+pick.card+': '+e.message,'err');}}
    $('#newCard').value='';$('#newName').value='';$('#newValidTo').value='';
    const h=$('#cardHint');h.hidden=!r.warning;h.textContent=r.warning||'';   // ostrzeżenie zostaje na widoku, toast znika
    if(r.warning)toast(r.warning,'err');
    loadUsers();}catch(e){toast('Błąd: '+e.message,'err');}}
// pytanie przy dodawaniu: undefined = anuluj, null = osobna karta, obiekt = wymiana tej karty
function replAsk(card,name,cands){return new Promise(res=>{const dlg=$('#replDlg');dlg.returnValue='';
  $('#replInfo').textContent='Nazwę „'+name+'” ma już '+(cands.length>1?'kilka kart':'karta')+' w panelu. Dodajesz kartę '+card+'.';
  $('#replList').innerHTML=cands.map((c,i)=>`<label style="display:block;margin:6px 0"><input type="radio" name="replPick" value="${i}" ${i?'':'checked'}>
    karta <b>${esc(c.card)}</b> - ${esc(c.name)}${c.dept?' · '+esc(c.dept):''} <span class="small ${c.on_ctrl?'warn-t':'muted'}">${c.on_ctrl?'jest w kontrolerze - straci dostęp':c.on_ctrl===false?'nie ma jej w kontrolerze - tylko połączenie w panelu':'nie sprawdzono kontrolera'}</span></label>`).join('');
  dlg.onclose=()=>{const v=dlg.returnValue;if(v==='replace'){const r=document.querySelector('input[name=replPick]:checked');res(cands[r?+r.value:0]);}
    else res(v==='add'?null:undefined);};
  dlg.showModal();});}
async function cardPickDenied(b,input,hint){b.disabled=true;
  try{const d=await api('/api/cards/last-denied');$(input).value=d.card;
    const h=$(hint);h.hidden=false;h.className='small';h.textContent='✅ Numer '+d.card+' odczytany z kontrolera - jest poprawny, nie trzeba go przeliczać.';
    toast('Karta '+d.card+' - odmowa na drzwiach #'+d.door+' '+(d.ago<60?d.ago+' s':Math.round(d.ago/60)+' min')+' temu','ok');}
  catch(e){toast(e.message,'err');}finally{b.disabled=false;}}
async function changeCard(id){const u=usersCache.find(x=>x.user_id===id)||{};if(!u.card)return;
  const dlg=$('#cardDlg');dlg.returnValue='';
  $('#cardDlgTitle').textContent='Zmień kartę: '+(u.name||'ID '+id);
  $('#cardDlgWarn').textContent='Obecna karta '+u.card+' straci dostęp do wszystkich drzwi.'+(u.blocked?' Karta jest zablokowana - najpierw ją odblokuj.':'');
  ['#cardDlgNew','#wgdCard','#wgdCtrl'].forEach(s=>$(s).value='');$('#wgdMsg').textContent='';$('#cardDlgHint').hidden=true;
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;const nw=$('#cardDlgNew').value.trim();
    if(!nw){toast('Podaj nowy numer karty','err');return;}
    if(!confirm('Zamienić kartę '+u.card+' na '+nw+'?\n\nKarta '+u.card+' od razu przestanie otwierać drzwi.'))return;
    try{const r=await api('/api/cards/replace',form({user_id:id,old:u.card,new:nw}));toast(r.msg,'ok');if(r.warning)toast(r.warning,'err');}
    catch(e){toast('Błąd: '+e.message,'err');}
    loadUsers();loadPeople();};
  dlg.showModal();$('#cardDlgNew').focus();}
async function blockCard(card,label){const dlg=$('#blockDlg');$('#blockDlgTitle').textContent='Zablokuj kartę: '+label;
  $('#blockReason').value='';$('#blockAllRow').hidden=connList.length<2;dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    try{const r=await api('/api/card/block',form({card,reason:$('#blockReason').value.trim(),everywhere:$('#blockAll').checked&&connList.length>1?'1':'0'}));
      toast(r.msg,'ok');(r.errors||[]).forEach(x=>toast(x,'err'));loadUsers();}catch(e){toast('Błąd: '+e.message,'err');}};
  dlg.showModal();$('#blockReason').focus();}
async function unblockCard(card){if(!confirm('Odblokować kartę '+card+'? Wrócą jej poprzednie uprawnienia do drzwi.'))return;
  try{const r=await api('/api/card/unblock',form({card}));toast(r.msg,'ok');loadUsers();}catch(e){toast('Błąd: '+e.message,'err');}}
let autoPoll=null,autoBusy=false;
function renderAuto(d){
  const on=!!d.active;
  $('#autoBtn').hidden=on;$('#autoStopBtn').hidden=!on;$('#autoStopBtn').disabled=false;
  if(on){if(!autoPoll)autoPoll=setInterval(autoTick,5000);
    $('#autoInfo').innerHTML='<span class="spin"></span> Tryb aktywny - przyłóż nową kartę do czytnika. Wyłączy się sam po dodaniu karty lub za '+d.left+' s.';return;}
  clearInterval(autoPoll);autoPoll=null;
  const l=d.last;if(!l){$('#autoInfo').textContent='';return;}
  const why={card:'dodano kartę',timeout:'upłynął limit czasu',manual:'zakończono ręcznie'}[l.reason]||'';
  $('#autoInfo').textContent='Tryb auto-dodawania wyłączony ('+why+'). Nowych kart: '+l.added+'.';
  if(l.added){toast('Dodano kartę - możesz nadać jej nazwę','ok');loadUsers();}
}
async function autoTick(){if(autoBusy)return;autoBusy=true;
  try{renderAuto(await api('/api/autoadd/state',{method:'POST'}));}catch(e){}finally{autoBusy=false;}}
async function autoAdd(){$('#autoBtn').disabled=true;
  try{const d=await api('/api/autoadd',{method:'POST'});renderAuto(d);toast('Tryb auto-dodawania aktywny','ok');
}
  catch(e){toast('Błąd: '+e.message,'err');}finally{$('#autoBtn').disabled=false;}}
async function autoStop(){$('#autoStopBtn').disabled=true;
  try{renderAuto(await api('/api/autoadd/stop',{method:'POST'}));toast('Tryb auto-dodawania wyłączony','ok');}
  catch(e){$('#autoStopBtn').disabled=false;toast('Błąd: '+e.message,'err');}}

// --- masowe dodawanie kart z wklejonej listy „numer + właściciel" ---
// Kontroler przyjmuje karty po jednej, więc przebieg idzie w tle - panel odpytuje o postęp co sekundę
// (tak samo jak przywracanie z kopii) i przeżywa przełączenie zakładki albo odświeżenie strony.
let bulkPoll=null;
const BULK_ST={new:'<span class="pill on">nowa</span>',present:'<span class="pill unv">już jest</span>',
  dup:'<span class="pill warn">powtórka</span>',error:'<span class="pill off">błąd</span>'};
function kartPl(n){const d=n%10,s=n%100;return n===1?'kartę':(d>=2&&d<=4&&!(s>=12&&s<=14)?'karty':'kart');}
function bulkClose(){$('#bulkBox').hidden=true;$('#bulkBox').innerHTML='';}
async function bulkPreview(b){const list=$('#bulkList').value;
  if(!list.trim()){toast('Wklej listę kart','err');return;}
  b.disabled=true;const box=$('#bulkBox');box.hidden=false;
  box.innerHTML='<span class="spin"></span> Porównywanie listy z kartami w kontrolerze...';
  try{renderBulkPreview(await api('/api/cards/bulk/preview',form({list})));}
  catch(e){box.innerHTML='<span class="err-t">'+esc(e.message)+'</span>';}
  finally{b.disabled=false;}}
function renderBulkPreview(p){
  const id=$('#bulkDept').value,dn=id?(depts.find(x=>String(x.id)===String(id))||{}).name||'':'',vt=$('#bulkValidTo').value;
  const c=p.counts,n=c.new+c.present;
  $('#bulkBox').innerHTML=`<div class="kv">
    <div class="small">Wierszy: <b>${p.rows.length}</b> · nowych kart: <b>${c.new}</b> · już w kontrolerze: <b>${c.present}</b>${c.dup?' · powtórek: <b>'+c.dup+'</b>':''}${c.error?' · <span style="color:var(--err)">błędnych: <b>'+c.error+'</b></span>':''}</div>
    <div class="tw" style="max-height:340px;overflow:auto;margin-top:8px"><table><thead><tr>
      <th>Nr karty</th><th>Nazwa właściciela</th><th>Stan</th><th>Uwaga</th></tr></thead><tbody>
      ${p.rows.map(r=>`<tr><td>${r.card?cardCell(r.card):'<span class="muted">—</span>'}</td>
        <td>${esc(r.name)||'<span class="muted">bez nazwy</span>'}</td><td>${BULK_ST[r.status]||''}</td>
        <td class="small muted">${esc(r.note)}</td></tr>`).join('')}</tbody></table></div>
    <div class="small" style="margin-top:8px">Do zapisania: <b>${n}</b> os.${id?' · dział: <b>'+esc(dn)+'</b>':' · <span class="muted">bez działu</span>'}${vt?' · ważne do <b>'+esc(vt)+'</b>':''}</div>
    ${c.error?'<div class="small" style="color:var(--warn);margin-top:4px">Wiersze z błędem będą pominięte - popraw je na liście wyżej i sprawdź ją ponownie.</div>':''}
    <div class="row" style="margin-top:10px">
      <button class="btn" onclick="bulkRun(this)" ${n?'':'disabled'}>Dodaj ${n} ${kartPl(n)}</button>
      <button class="btn ghost" onclick="bulkClose()">Anuluj</button></div></div>`;}
async function bulkRun(b){b.disabled=true;
  try{renderBulk(await api('/api/cards/bulk',form({list:$('#bulkList').value,dept_id:$('#bulkDept').value,
    valid_to:$('#bulkValidTo').value})));}
  catch(e){b.disabled=false;toast('Błąd: '+e.message,'err');}}
function renderBulk(s){const box=$('#bulkBox');box.hidden=false;$('#bulkCheckBtn').disabled=!!s.running;
  if(s.running){if(!bulkPoll)bulkPoll=setInterval(async()=>{try{renderBulk(await api('/api/cards/bulk'));}catch(e){}},1000);
    box.innerHTML='<div class="kv"><span class="spin"></span> Dodawanie kart z listy: '+Math.min(s.done+1,s.total)+' z '+s.total
      +(s.current?' ('+esc(s.current)+')':'')+' - nie rozłączaj kontrolera.</div>';return;}
  clearInterval(bulkPoll);bulkPoll=null;
  const l=['dodano nowych kart: <b>'+s.added+'</b>'];
  if(s.assigned)l.push('przypisano do działu '+(s.dept?'„'+esc(s.dept)+'”':'')+': <b>'+s.assigned+'</b> os.');
  if(s.valid_to)l.push('ważność do <b>'+esc(s.valid_to)+'</b>');
  box.innerHTML=`<div class="kv">${s.stopped?'<b style="color:var(--err)">Dodawanie przerwane: '+esc(s.stopped)+'</b>'
      :'<b style="color:var(--ok)">Lista dodana</b>'}
    <div class="small" style="margin-top:4px">${l.join(' · ')}</div>
    ${s.failed.length?'<div class="small" style="color:var(--warn);margin-top:6px">Nie dodano:<br>'
      +s.failed.map(f=>esc((f.name?f.name+' - ':'')+'karta '+f.card+': '+f.error)).join('<br>')+'</div>':''}
    ${s.warning?'<div class="small" style="color:var(--warn);margin-top:6px">'+esc(s.warning)+'</div>':''}
    <div class="row" style="margin-top:10px"><button class="btn ghost" onclick="bulkClose()">Zamknij</button></div></div>`;
  if(!s.stopped&&!s.failed.length)$('#bulkList').value='';
  loadUsers();loadPeople();
  toast(s.stopped?'Dodawanie listy przerwane':'Dodano '+s.added+' '+kartPl(s.added),s.stopped?'err':'ok');}
async function bulkResume(){try{const s=await api('/api/cards/bulk');if(s.running)renderBulk(s);}catch(e){}}
function isoDay(off){const d=new Date();d.setDate(d.getDate()+off);return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');}
function vQuick(days){if(!days){$('#userDlgFrom').value='';$('#userDlgTo').value='';return;}
  if(!$('#userDlgFrom').value||$('#userDlgFrom').value>isoDay(0))$('#userDlgFrom').value=isoDay(0);$('#userDlgTo').value=isoDay(days);}
async function editUser(id){
  const u=usersCache.find(x=>x.user_id===id)||{};
  let d;try{d=await api('/api/user?user_id='+encodeURIComponent(id)+'&card='+encodeURIComponent(u.card||''));}catch(e){toast('Błąd: '+e.message,'err');return;}
  const names=(lastStatus&&lastStatus.doors_list)||[];
  $('#userDlgTitle').textContent='Użytkownik ID '+d.user_id+' · karta '+d.card;
  $('#userDlgName').value=d.name||'';
  $('#userDlgDoors').innerHTML=(u.blocked?'<p class="small warn-t" style="margin:0 0 6px">⛔ Karta zablokowana - dostęp wróci po odblokowaniu.</p>':'')+d.access.map((a,i)=>{const n=(names.find(x=>x.n===i+1)||{}).name;
    return `<label style="display:block;margin:6px 0"><input type="checkbox" data-known="${a!==null}" ${a?'checked':''} ${a===null||u.blocked?'disabled':''}>
      Drzwi #${i+1}${n?' – '+esc(n):''}${a===null?' <span class="muted small">(brak w formularzu)</span>':''}</label>`;}).join('');
  const deflt=u.valid_from==='2011-01-01'&&u.valid_to==='2029-12-31';
  $('#userDlgValid').hidden=!usersUdp||!u.valid_to;
  $('#userDlgFrom').value=deflt?'':(u.valid_from||'');$('#userDlgTo').value=deflt?'':(u.valid_to||'');
  const orig=[$('#userDlgFrom').value,$('#userDlgTo').value].join('|');
  const dlg=$('#userDlg');dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    const access=u.blocked?'':[...document.querySelectorAll('#userDlgDoors input')].map(c=>c.dataset.known==='true'?(c.checked?'1':'0'):'').join(',');
    try{const r=await api('/api/edituser',form({user_id:id,card:d.card,name:$('#userDlgName').value.trim(),access}));toast(r.msg,'ok');if(r.warning)toast(r.warning,'err');
      if(!$('#userDlgValid').hidden&&[$('#userDlgFrom').value,$('#userDlgTo').value].join('|')!==orig){
        const v=await api('/api/card/validity',form({card:d.card,valid_from:$('#userDlgFrom').value,valid_to:$('#userDlgTo').value}));toast(v.msg,'ok');}
      loadUsers();}
    catch(e){toast('Błąd: '+e.message,'err');loadUsers();}};
  dlg.showModal();}
async function delUser(id,label){if(!confirm('Usunąć: '+label+' (ID '+id+')?'))return;
  const u=usersCache.find(x=>x.user_id===id)||{};
  try{await api('/api/deluser',form({user_id:id,card:u.card||''}));toast('Usunięto ID '+id,'ok');loadUsers();}
  catch(e){toast('Błąd: '+e.message,'err');}}

// --- spis kart panelu (tabela people) - usuwanie kart, których nie ma już w żadnym kontrolerze ---
let dirData=null,dirBusy=false;
async function loadDirectory(){if(dirBusy)return;dirBusy=true;
  $('#dirBody').innerHTML='<tr><td colspan="6" class="muted"><span class="spin"></span> Sprawdzanie kart w kontrolerach...</td></tr>';
  try{dirData=await api('/api/people/directory');renderDirectory();}
  catch(e){$('#dirBody').innerHTML='<tr><td colspan="6" class="muted">'+esc(e.message)+'</td></tr>';}
  finally{dirBusy=false;}}
function renderDirectory(){const d=dirData;if(!d)return;
  const all=$('#dirAll').checked,orphans=d.people.filter(p=>!p.on.length);
  const list=all?d.people:orphans;
  $('#dirCount').textContent='w spisie: '+d.people.length+' · poza kontrolerami: '+orphans.length;
  const op=can('operator');
  $('#dirBody').innerHTML=list.length?list.map(p=>`<tr><td>${cardCell(p.card)}</td>
    <td>${p.name?esc(p.name):'<span class="muted">bez nazwy</span>'}</td><td>${p.dept?esc(p.dept):'<span class="muted">—</span>'}</td>
    <td>${p.on.length?esc(p.on.join(', ')):'<span class="muted">brak</span>'}</td>
    <td style="white-space:nowrap">${p.last_seen?esc(p.last_seen):'<span class="muted">—</span>'}</td>
    <td style="white-space:nowrap">${p.replaced_by?`<span class="small muted">🔁 zastąpiona kartą ${esc(p.replaced_by)}</span> `:''}${op&&!p.on.length&&!p.replaced_by?`<button class="btn ghost sm" onclick="linkCard(this,'${esc(p.card)}')" title="Osoba dostała nową kartę - czas pracy i „kto w środku” policzą obie razem">🔁 Zastąpiona kartą…</button> `:''}${op&&!p.on.length?`<button class="btn danger sm" onclick="forgetCard(this,'${esc(p.card)}')">Usuń ze spisu</button>`:''}</td></tr>`).join('')
    :'<tr><td colspan="6" class="muted">'+(all?'Spis jest pusty':'Wszystkie karty ze spisu są zapisane w połączonych kontrolerach')+'</td></tr>';
  const notes=[];
  if(!d.checked.length&&!d.unchecked.length)notes.push('Brak połączonego kontrolera - panel nie wie, które karty są w kontrolerach, więc wszystkie widać jako „brak”.');
  if(d.unchecked.length)notes.push('Nie odczytano listy kart z: '+d.unchecked.join(', ')+' - karty z tych kontrolerów mogą tu wyglądać na nieużywane.');
  $('#dirNote').textContent=notes.join(' ');$('#dirNote').hidden=!notes.length;}
async function linkCard(b,card){const p=(dirData&&dirData.people.find(x=>x.card===card))||{};
  const nw=(prompt('Karta '+card+(p.name?' („'+p.name+'”)':'')+' została zastąpiona kartą o numerze:\n\n(numer tak, jak widzi go kontroler - np. z listy użytkowników)')||'').trim();
  if(!nw)return;b.disabled=true;
  try{dirData=await api('/api/cards/link',form({old:card,new:nw}));toast(dirData.msg,'ok');renderDirectory();loadPeople();}
  catch(e){toast('Błąd: '+e.message,'err');b.disabled=false;}}
async function forgetCard(b,card){const p=(dirData&&dirData.people.find(x=>x.card===card))||{};
  if(!confirm('Usunąć kartę '+card+(p.name?' („'+p.name+'”)':'')+' ze spisu panelu?\n\nZniknie jej nazwa i dział. Wpisy w logu zostaną, ale bez nazwy. Kontrolerów to nie zmienia.'))return;
  b.disabled=true;
  try{dirData=await api('/api/people/forget',form({card,name:p.name||''}));toast(dirData.msg,'ok');renderDirectory();loadPeople();}
  catch(e){toast('Błąd: '+e.message,'err');b.disabled=false;}}

// --- kopia zapasowa użytkowników (karty + nazwy + działy; bez uprawnień do drzwi) ---
let restoreData=null,restorePoll=null;
async function downloadBackup(b){if(b)b.disabled=true;toast('Odczyt użytkowników z kontrolera...');
  try{const r=await fetch('/api/backup/users.json');
    if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error||('HTTP '+r.status));}
    const name=(/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition')||'')||[])[1]||'acb-uzytkownicy.json';
    const blob=await r.blob(),d=JSON.parse(await blob.text());
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;
    document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},1000);
    toast('Zapisano kopię: '+d.users_total+' użytkowników, działów: '+d.departments.length,'ok');
  }catch(e){toast('Błąd kopii zapasowej: '+e.message,'err');}
  finally{if(b)b.disabled=false;}}
async function restorePreview(inp){const f=inp.files[0];inp.value='';if(!f)return;
  const box=$('#restoreBox');box.hidden=false;box.innerHTML='<span class="spin"></span> Porównywanie kopii z kontrolerem...';
  try{restoreData=await f.text();renderRestorePreview(await api('/api/backup/preview',form({data:restoreData})),f.name);}
  catch(e){restoreData=null;box.innerHTML='<span class="err-t">'+esc(e.message)+'</span>';}}
function renderRestorePreview(p,file){const c=p.controller||{};
  const who=[c.name,c.model,c.device_no&&'nr '+c.device_no,c.host].filter(Boolean).map(esc).join(' · ');
  const deptName=d=>d?esc(d):'<span class="muted">bez działu</span>';
  const newDepts=p.departments.filter(d=>!d.exists);
  $('#restoreBox').innerHTML=`<div class="kv">
    <div><b>${esc(file)}</b> <span class="muted small">· kopia z ${esc(p.created)}${who?' · '+who:''}</span></div>
    ${p.same_controller?'':'<div class="small" style="color:var(--warn);margin-top:4px">Kopia pochodzi z innego kontrolera niż połączony.</div>'}
    <div class="small" style="margin-top:8px">Użytkowników w kopii: <b>${p.users}</b> · już w kontrolerze: <b>${p.present}</b> · brakuje: <b>${p.add.length}</b>
      ${p.extra?` · w kontrolerze spoza kopii: <b>${p.extra}</b> <span class="muted">(zostaną bez zmian)</span>`:''}</div>
    <div class="small" style="margin-top:4px">Działy w kopii: ${p.departments.map(d=>esc(d.name)+' ('+d.users+')'+(d.exists?'':' <span class="pill unv">nowy</span>')).join(', ')||'<span class="muted">brak</span>'}</div>
    ${p.add.length?`<details style="margin-top:8px"><summary class="small">Karty do dodania (${p.add.length})</summary><table><thead><tr><th>Nr karty</th><th>Nazwa</th><th>Dział</th></tr></thead><tbody>
      ${p.add.map(u=>`<tr><td>${esc(u.card)}</td><td>${esc(u.name)}</td><td>${deptName(u.dept)}</td></tr>`).join('')}</tbody></table></details>`:''}
    ${p.moves.length?`<details style="margin-top:8px"><summary class="small">Zmiany działów (${p.moves.length})</summary><table><thead><tr><th>Nr karty</th><th>Nazwa</th><th>Teraz</th><th>Z kopii</th></tr></thead><tbody>
      ${p.moves.map(u=>`<tr><td>${esc(u.card)}</td><td>${esc(u.name)}</td><td>${deptName(u.from)}</td><td>${deptName(u.to)}</td></tr>`).join('')}</tbody></table></details>`:''}
    <label class="small" style="display:block;margin-top:12px"><input type="checkbox" id="rsCards" ${p.add.length?'checked':'disabled'}>
      Dodaj do kontrolera brakujące karty (${p.add.length}) <span class="muted">- z dostępem do wszystkich drzwi, jak każda nowa karta; uprawnienia ustaw potem w „Edytuj / dostęp”</span></label>
    <label class="small" style="display:block;margin-top:4px"><input type="checkbox" id="rsDepts" checked>
      Przywróć działy i przypisania${newDepts.length?' (nowe działy: '+newDepts.length+')':''}${p.moves.length?', zmiany: '+p.moves.length:''}</label>
    <p class="muted small" style="margin:6px 0 0">Nazwy kart, które już są w kontrolerze, nie są zmieniane. Nic nie jest usuwane.</p>
    <div class="row" style="margin-top:10px"><button class="btn" id="rsBtn" onclick="restoreRun(this)">Przywróć</button>
      <button class="btn ghost" onclick="restoreClose()">Anuluj</button></div></div>`;}
async function restoreResume(){try{const s=await api('/api/backup/restore');if(s.running)renderRestore(s);}catch(e){}}
function restoreClose(){restoreData=null;$('#restoreBox').hidden=true;$('#restoreBox').innerHTML='';}
async function restoreRun(b){if(!restoreData)return;
  const cards=$('#rsCards').checked,dpt=$('#rsDepts').checked;
  if(!cards&&!dpt){toast('Zaznacz, co przywrócić','err');return;}
  b.disabled=true;
  try{renderRestore(await api('/api/backup/restore',form({data:restoreData,cards:cards?'1':'0',depts:dpt?'1':'0'})));}
  catch(e){b.disabled=false;toast('Błąd: '+e.message,'err');}}
function renderRestore(s){const box=$('#restoreBox');box.hidden=false;$('#restorePick').disabled=!!s.running;
  if(s.running){if(!restorePoll)restorePoll=setInterval(async()=>{try{renderRestore(await api('/api/backup/restore'));}catch(e){}},1000);
    box.innerHTML='<div class="kv"><span class="spin"></span> Przywracanie z kopii'+(s.total?': karta '+Math.min(s.done+1,s.total)+' z '+s.total
      +(s.current?' ('+esc(s.current)+')':''):'...')+' - nie rozłączaj kontrolera.</div>';return;}
  clearInterval(restorePoll);restorePoll=null;restoreData=null;
  const l=[];
  if(s.add_cards)l.push('dodano kart: <b>'+s.added+'</b>'+(s.total>s.added?' z '+s.total:''));
  if(s.set_depts)l.push('nowe działy: <b>'+s.depts_created+'</b>, przypisania z kopii: <b>'+s.assigned+'</b>');
  box.innerHTML=`<div class="kv">${s.stopped?'<b style="color:var(--err)">Przywracanie przerwane: '+esc(s.stopped)+'</b>':'<b style="color:var(--ok)">Przywrócono z kopii</b>'}
    <div class="small" style="margin-top:4px">${l.join(' · ')}</div>
    ${s.failed.length?'<div class="small" style="color:var(--warn);margin-top:6px">Nie dodano:<br>'+s.failed.map(f=>esc((f.name?f.name+' - ':'')+'karta '+f.card+': '+f.error)).join('<br>')+'</div>':''}
    ${s.warning?'<div class="small" style="color:var(--warn);margin-top:6px">'+esc(s.warning)+'</div>':''}
    <div class="row" style="margin-top:10px"><button class="btn ghost" onclick="restoreClose()">Zamknij</button></div></div>`;
  loadUsers();loadPeople();
  toast(s.stopped?'Przywracanie przerwane':'Przywrócono z kopii',s.stopped?'err':'ok');}

// --- log przejść: kopia logu kontrolera w panelu (filtry po pracowniku / dziale / datach) ---
let logPage=1,logPages=1,logBusy=false;
// filtry: prefiks id „f” = log przejść, „w” = czas pracy
function filterQuery(k,extra){const p=new URLSearchParams({card:$('#'+k+'Card').value,dept:$('#'+k+'Dept').value,
  from:$('#'+k+'From').value,to:$('#'+k+'To').value,...(extra||{})});return p.toString();}
function renderPersonFilter(k){const dept=$('#'+k+'Dept').value;
  const list=people.filter(p=>!dept||(dept==='none'?!p.dept_id:String(p.dept_id)===dept));
  setOptions($('#'+k+'Card'),'<option value="">Wszyscy pracownicy</option>'+list.map(p=>
    `<option value="${esc(p.card)}">${esc(p.name||'(bez nazwy)')} · karta ${esc(p.card)}${p.dept&&!dept?' · '+esc(p.dept):''}</option>`).join(''));
}
async function loadPeople(){try{const d=await api('/api/people');people=d.people;depts=d.departments;renderDepts();renderPersonFilter('f');renderPersonFilter('w');}catch(e){}}
function filtersChanged(){logPage=1;loadLog();}
function clearFilters(k){$('#'+k+'Dept').value='';renderPersonFilter(k);['Card','From','To'].forEach(x=>$('#'+k+x).value='');
  if(k==='w')wtFiltersChanged();else filtersChanged();}
function dirCell(r){
  if(/Remote Open/i.test(r.status))return '<span class="e">🔓</span> otwarcie z panelu';
  if(r.passed)return '<span class="e" title="kontroler odrzucił kartę w godzinach jej działu (brak PIN-u), drzwi otworzył panel">🔓➡️🚪</span> wejście (otworzył panel)';
  const d={in:'<span class="e">➡️🚪</span> wejście',out:'<span class="e">🚪➡️</span> wyjście'}[r.reader];
  if(!d)return '<span class="e" title="zdarzenie urządzenia">⚙️</span>';
  return (r.granted?'':'<span class="e" title="odmowa dostępu">⛔</span> ')+d;
}
async function loadLog(){if(logBusy)return;logBusy=true;
  try{const d=await api('/api/log?'+filterQuery('f',{page:logPage}));
    logPage=d.page;logPages=d.pages;renderSync(d.sync);
    $('#pageInfo').textContent='Strona '+d.page+' z '+d.pages+' · wpisów: '+d.total;
    if(!d.rows.length){$('#swipeBody').innerHTML='<tr><td colspan="7" class="muted">'+(d.sync.stored?'Brak wpisów dla wybranych filtrów':(d.sync.running?'<span class="spin"></span> Pobieranie logu z kontrolera...':'Brak wpisów'))+'</td></tr>';return;}
    $('#swipeBody').innerHTML=d.rows.map(r=>`<tr class="${r.granted||r.passed?'grant':'deny'}"><td class="muted">${esc(String(r.record))}</td>
      <td class="dir">${dirCell(r)}</td>
      <td>${r.card?(esc(r.person||r.name)||'<span class="muted">bez nazwy</span>')+'<br><span class="muted small">karta '+cardCell(r.card)+'</span>':'—'}</td>
      <td>${r.dept?esc(r.dept):'<span class="muted">—</span>'}</td><td>${r.door?'#'+r.door:'—'}</td>
      <td class="small">${esc(r.status)}${r.reason_text?'<br><span class="'+(r.on_ctrl===false?'warn-t':'muted')+'" title="'+(r.on_ctrl===false?'Stan listy kart kontrolera teraz. Nazwa pracownika pochodzi ze spisu kart panelu (Pracownicy i karty), nie z kontrolera.':'Powód odmowy zapisany przez kontroler')+'">'+esc(r.reason_text)+'</span>':''}</td><td style="white-space:nowrap">${esc(r.time)}</td></tr>`).join('');
  }catch(e){$('#swipeBody').innerHTML='<tr><td colspan="7" class="muted">'+esc(e.message)+'</td></tr>';}
  finally{logBusy=false;}}
function logNav(n){logPage={first:1,prev:Math.max(logPage-1,1),next:Math.min(logPage+1,logPages),last:logPages}[n];loadLog();}
function renderSync(s){if(!s)return;
  let t='W panelu zapisano wpisów: '+s.stored+(s.newest?' (najnowszy: '+s.newest+')':'')+'.';
  if(s.running)t='<span class="spin"></span> Pobieranie logu z kontrolera'+(s.pages?': strona '+s.page+' z '+s.pages:'...')+', nowych wpisów: '+s.added+'. '+t;
  else if(s.error)t='<span class="warn-t">Pobieranie przerwane: '+esc(s.error)+'.</span> '+t;
  $('#syncInfo').innerHTML=t;$('#syncBtn').disabled=!!s.running;
}
// pobiera nowe wpisy z kontrolera (w tle na serwerze) i czeka na koniec; log odświeża w trakcie
let syncWait=null;
function syncLog(){
  if(syncWait)return syncWait;
  syncWait=(async()=>{
    let s;try{s=await api('/api/swipe/sync',{method:'POST'});}catch(e){toast('Błąd pobierania logu: '+e.message,'err');return null;}
    let n=0;
    while(s.running){renderSync(s);if(++n%3===0)loadLog();
      await new Promise(r=>setTimeout(r,1000));
      try{s=await api('/api/swipe/sync');}catch(e){break;}}
    renderSync(s);return s;
  })().finally(()=>{syncWait=null;});
  return syncWait;
}
async function refreshLog(){const s=await syncLog();loadLog();loadPeople();
  if(s&&s.added)toast('Pobrano nowych wpisów: '+s.added,'ok');}
function toggleAuto(){if($('#auto').checked)autoTimer=setInterval(()=>{if(connected&&!document.hidden&&!syncWait)syncLog().then(s=>{if(s&&s.added){loadLog();loadPeople();}});},5000);else{clearInterval(autoTimer);autoTimer=null;}}
function openLogTab(){loadPeople();loadTracking();loadLog();syncLog().then(s=>{if(s){loadLog();if(s.added)loadPeople();}});}

// --- czas pracy ---
function fmtDur(sec){const m=Math.round(sec/60);return Math.floor(m/60)+' h '+String(m%60).padStart(2,'0')+' min';}
const hm=t=>t?t.slice(11,16):'';
let wtData=null,wtSeq=0,wtBusy=false;
function wtReady(){return !!(tracking&&tracking.supported&&tracking.ready!==false&&tracking.doors.some(d=>d.enabled));}
async function openWorkTab(){loadPeople();loadWorkSettings();await loadTracking();if(wtReady())loadWorktime();}
function wtFiltersChanged(){if(wtReady())loadWorktime();}
async function loadWorktime(){
  const seq=++wtSeq;wtBusy=true;$('#wtBtn').disabled=true;  // nowsze przeliczenie (zmiana filtra w trakcie) unieważnia starsze
  $('#wtInfo').innerHTML='<span class="spin"></span> Pobieranie nowych wpisów z kontrolera...';
  try{
    await syncLog();if(seq!==wtSeq)return;
    $('#wtInfo').innerHTML='<span class="spin"></span> Liczenie czasu pracy...';
    const d=await api('/api/worktime?'+filterQuery('w',{place:$('#wtPlace').value}));
    if(seq!==wtSeq)return;wtData=d;renderWorktime();
  }catch(e){if(seq!==wtSeq)return;$('#wtInfo').innerHTML='<span class="warn-t">'+esc(e.message)+'</span>';$('#wtBody').innerHTML='';}
  finally{if(seq===wtSeq){wtBusy=false;renderTracking();}}
}
function fmtBal(sec){return (sec<0?'−':'+')+fmtDur(Math.abs(sec));}
function renderWorktime(){const d=wtData;
  const place=$('#wtPlace').selectedOptions[0];
  const inside=d.rows.filter(r=>r.inside).length;
  $('#wtInfo').innerHTML=`Okres <b>${esc(d.from)}</b> – <b>${esc(d.to)}</b> · ${esc(place?place.textContent:'')} · pracowników: <b>${d.rows.length}</b> · łącznie <b>${fmtDur(d.seconds)}</b> · dni robocze do dziś: <b>${d.work_days}</b> z ${d.work_days_total}`+
    (inside?` · <span class="ok-t">🟢 teraz w środku: ${inside}</span>`:'')+` <span class="muted">(stan na ${esc(d.generated)})</span>`;
  if(!d.rows.length){$('#wtBody').innerHTML='<p class="muted">Brak odbić na zaznaczonych drzwiach w tym okresie.</p>';return;}
  $('#wtBody').innerHTML=`<table style="margin-top:12px"><thead><tr><th></th><th>Pracownik</th><th>Dział</th><th>Dni z pracą</th><th>Łączny czas</th><th title="Norma do dziś i saldo (przepracowane − norma)">Norma / saldo</th><th>Nadgodziny</th><th>Spóźnienia</th><th>Uwagi</th></tr></thead><tbody>`+
    d.rows.map((r,i)=>`<tr class="wt" onclick="toggleWt(${i})"><td class="muted" id="wtArr${i}">▸</td>
      <td><b>${esc(r.name)||'<span class="muted">bez nazwy</span>'}</b>${r.inside?' <span class="pill on">🟢 w środku</span>':''}<br><span class="muted small">karta ${esc(r.card)}</span></td>
      <td>${r.dept?esc(r.dept):'<span class="muted">—</span>'}</td><td>${r.days_worked}</td>
      <td><b>${fmtDur(r.seconds)}</b><br><span class="muted small">${r.days_worked?'śr. '+fmtDur(r.seconds/r.days_worked):''}</span></td>
      <td>${r.balance===null?'<span class="muted">—</span>':fmtDur(r.norm_seconds)+'<br><span class="small '+(r.balance<0?'warn-t':'ok-t')+'">'+fmtBal(r.balance)+'</span>'}</td>
      <td>${r.overtime?fmtDur(r.overtime):'<span class="muted">—</span>'}</td>
      <td>${r.late_count?'<span class="warn-t">'+r.late_count+'×</span> <span class="muted small">('+r.late_minutes+' min)</span>':r.shift_start?'<span class="muted">0</span>':'<span class="muted" title="Dział nie ma ustawionego początku zmiany">—</span>'}</td>
      <td>${r.issues?'<span class="warn-t">❓ '+r.issues+'</span> ':''}${r.absent.length?'<span class="warn-t" title="Dni robocze bez odbić: '+esc(r.absent.join(', '))+'">🚫 '+r.absent.length+'</span> ':''}${r.corrections?'<span class="corr" title="Korekty ręczne">✍️ '+r.corrections+'</span>':''}${!r.issues&&!r.absent.length&&!r.corrections?'<span class="muted">—</span>':''}</td></tr>
      <tr class="wtd" id="wtDet${i}" hidden><td colspan="9"></td></tr>`).join('')+'</tbody></table>';
}
function toggleWt(i){const tr=$('#wtDet'+i),r=wtData.rows[i];tr.hidden=!tr.hidden;$('#wtArr'+i).textContent=tr.hidden?'▸':'▾';
  if(tr.hidden)return;
  const op=can('operator');
  const add=(card,day,reader,hhmm,label)=>op?` <button class="iconbtn" onclick="event.stopPropagation();corrOpen('${esc(card)}','${day}','${reader}','${hhmm}')">✍️ ${label}</button>`:'';
  const man=s=>(s.manual||[]).map(m=>` <span class="corr" title="korekta: ${esc(m.note)} (${esc(m.login)})">✍️</span>`+(op?`<button class="iconbtn del" style="padding:1px 6px" title="Usuń korektę ${esc(m.time.slice(11,16))}" onclick="event.stopPropagation();corrDelete(${m.id})">×</button>`:'')).join('');
  const st={ok:'',ongoing:' <span class="ok-t">🟢 w środku</span>',no_out:' <span class="warn-t">❓ brak odbicia przy wyjściu - nie liczone</span>'};
  const days=r.days.map(dy=>[dy.date,`<tr><td style="white-space:nowrap"><b>${esc(dy.date)}</b>${dy.free?'<br><span class="muted small">'+esc(dy.free==='weekend'?'weekend':dy.free)+'</span>':''}${dy.late?'<br><span class="warn-t small">spóźnienie '+dy.late+' min</span>':''}</td><td>`+
      dy.sessions.map(s=>`<span class="e">➡️🚪</span> ${hm(s.in)} → ${s.state==='ok'?'<span class="e">🚪➡️</span> '+hm(s.out)+(s.out.slice(0,10)!==dy.date?' <span class="muted">('+esc(s.out.slice(0,10))+')</span>':''):s.state==='ongoing'?'…':'❓'}${s.seconds?' <span class="muted">('+fmtDur(s.seconds)+')</span>':''}${st[s.state]}${man(s)}${s.state==='no_out'?add(r.card,dy.date,'out','16:00','dopisz wyjście'):''}`).concat(
      dy.stray.map(t=>`❓ → <span class="e">🚪➡️</span> ${hm(t)} <span class="warn-t">brak odbicia przy wejściu - nie liczone</span>${add(r.card,dy.date,'in','08:00','dopisz wejście')}`)).join('<br>')+
      `</td><td style="white-space:nowrap"><b>${dy.seconds?fmtDur(dy.seconds):'—'}</b>${dy.overtime?'<br><span class="muted small">nadgodziny '+fmtDur(dy.overtime)+'</span>':''}</td></tr>`]);
  const absent=r.absent.map(dt=>[dt,`<tr><td><b>${esc(dt)}</b></td><td><span class="warn-t">🚫 dzień roboczy bez odbić</span>${add(r.card,dt,'in','08:00','dopisz wejście')}</td><td>—</td></tr>`]);
  const all=days.concat(absent).sort((x,y)=>x[0]<y[0]?-1:x[0]>y[0]?1:0).map(x=>x[1]);
  tr.firstElementChild.innerHTML=(all.length?'<table><thead><tr><th>Dzień</th><th>Wejście → wyjście</th><th>Czas</th></tr></thead><tbody>'+all.join('')+'</tbody></table>':'<span class="muted small">Brak odbić w tym okresie.</span>')
    +(op?`<div style="margin-top:8px">${add(r.card,isoDay(0),'in','08:00','dopisz odbicie')}</div>`:'');
}
let corrCard='';
function corrOpen(card,day,reader,hhmm){const r=(wtData.rows||[]).find(x=>x.card===card)||{};corrCard=card;
  $('#corrWho').textContent=(r.name||'karta '+card)+(r.dept?' · '+r.dept:'');
  $('#corrReader').value=reader;$('#corrTime').value=day+'T'+hhmm;$('#corrNote').value='';
  const dlg=$('#corrDlg');dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    try{const x=await api('/api/work/correction',form({card:corrCard,time:$('#corrTime').value,reader:$('#corrReader').value,note:$('#corrNote').value}));
      toast(x.msg,'ok');loadWorktime();}catch(e){toast('Błąd: '+e.message,'err');}};
  dlg.showModal();$('#corrNote').focus();}
async function corrDelete(id){if(!confirm('Usunąć tę korektę? Zostanie ślad w dzienniku działań.'))return;
  try{const x=await api('/api/work/correction/delete',form({id}));toast(x.msg,'ok');loadWorktime();}catch(e){toast('Błąd: '+e.message,'err');}}
function printWorktime(){const m=($('#wFrom').value||isoDay(0)).slice(0,7);
  window.open('/print/worktime?'+new URLSearchParams({month:m,card:$('#wCard').value,dept:$('#wDept').value,place:$('#wtPlace').value}),'_blank');}
let wsData=null;
async function loadWorkSettings(){if(!can('admin'))return;
  try{wsData=await api('/api/work/settings');const c=wsData.settings;
    $('#wsNorm').value=c.norm_min/60;$('#wsTol').value=c.late_tolerance;$('#wsPl').checked=!!c.holidays_pl;
    $('#wsDepts').innerHTML=wsData.departments.map(d=>{const v=c.depts[String(d.id)]||{};
      return `<tr data-dept="${d.id}"><td>🏷️ ${esc(d.name)}</td><td><input type="number" class="ws-norm" min="0" max="24" step="0.25" style="width:100px" value="${v.norm_min!==undefined?v.norm_min/60:''}" placeholder="${c.norm_min/60}"></td>
        <td><input type="time" class="ws-start" value="${esc(v.start||'')}"></td></tr>`;}).join('')||'<tr><td colspan="3" class="muted">Brak działów.</td></tr>';}
  catch(e){toast('Błąd: '+e.message,'err');}}
async function saveWorkSettings(b){b.disabled=true;
  const depts={};document.querySelectorAll('#wsDepts tr[data-dept]').forEach(tr=>{const n=tr.querySelector('.ws-norm').value,st=tr.querySelector('.ws-start').value;
    const v={};if(n!=='')v.norm_min=Math.round(parseFloat(n)*60);if(st)v.start=st;if(Object.keys(v).length)depts[tr.dataset.dept]=v;});
  try{await api('/api/work/settings',form({settings:JSON.stringify({norm_min:Math.round(parseFloat($('#wsNorm').value||'8')*60),late_tolerance:parseInt($('#wsTol').value||'0'),holidays_pl:$('#wsPl').checked,depts})}));
    toast('Zapisano ustawienia czasu pracy','ok');if(wtReady())loadWorktime();}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}
async function exportWorktime(b){b.disabled=true;
  try{await syncLog();
    const r=await fetch('/api/worktime.csv?'+filterQuery('w',{place:$('#wtPlace').value}));
    if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error||('HTTP '+r.status));}
    const name=(/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition')||'')||[])[1]||'czas-pracy.csv';
    const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=name;
    document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},1000);
  }catch(e){toast('Błąd eksportu: '+e.message,'err');}
  finally{b.disabled=false;}}

// --- drzwi / config ---
async function openDoor(n){if(!confirm('Otworzyć drzwi #'+n+' na: '+ctrlLabel(lastStatus)+' ('+lastStatus.host+')?'))return;
  try{const d=await api('/api/open',form({door:n}));toast('Drzwi #'+n+': '+(d.msg||'otwarto'),'ok');}catch(e){toast('Błąd: '+e.message,'err');}}
async function saveDoor(n){const b=$('#doorSave'+n),nm=$('#doorName'+n),dl=$('#doorDelay'+n);
  const chName=nm.value!==nm.dataset.orig,chDelay=dl.value!==dl.dataset.orig;
  if(!chName&&!chDelay){toast('Drzwi #'+n+': brak zmian do zapisania','');return;}
  if(b.disabled)return;b.disabled=true;const msgs=[];
  try{
    if(chName){const d=await api('/api/doorname',form({door:n,name:nm.value}));nm.dataset.orig=nm.value;msgs.push(d.msg);}
    if(chDelay){const d=await api('/api/doordelay',form({door:n,sec:dl.value}));dl.dataset.orig=dl.value;msgs.push(d.msg);}
    toast(msgs.join(' · '),'ok');
  }catch(e){toast((msgs.length?msgs.join(' · ')+' · ':'')+'Błąd: '+e.message,'err');}
  finally{b.disabled=false;loadStatus();}}
async function saveEvents(){try{await api('/api/events',form({enabled:$('#events').value==='1'?'1':'0'}));toast('Zapisano','ok');loadStatus();}catch(e){toast('Błąd: '+e.message,'err');}}
// --- Super Card / hasła otwarcia (wartości czytane z formularzy kontrolera) ---
let codesBusy=false;
function renderSuperCards(cards){
  $('#scBody').innerHTML=[1,2].map(n=>{const v=!!cards[n-1];return `<tr><td>Super Card ${n}</td>
    <td>${v?'<b>🔒 karta zapisana</b>':'<span class="muted">pusty</span>'}</td>
    <td><input type="password" id="sc${n}" maxlength="19" inputmode="numeric" placeholder="Numer karty" style="width:170px" autocomplete="new-password" oninput="cardHint('#sc${n}','#scHint',true)"></td>
    <td style="text-align:right;white-space:nowrap"><button class="btn" onclick="saveSuperCard(${n},this)">Zapisz</button>
      ${v?`<button class="iconbtn del" onclick="saveSuperCard(${n},this,true)">Usuń</button>`:''}</td></tr>`;}).join('');
}
function renderPasswords(doorPwds,readable){
  const s=lastStatus,multi=(s.doors||1)>1;
  $('#dpBody').innerHTML=doorList(s).map(dr=>{const pwds=doorPwds&&doorPwds[dr.n-1];
    const head=multi?`<tr><td colspan="4" style="padding-top:14px"><b>Drzwi ${esc(doorLabel(dr))}</b></td></tr>`:'';
    return head+[1,2,3,4].map(n=>{const v=pwds&&pwds[n-1];
    const st=readable?(v?'<b>🔒 hasło ustawione</b>':'<span class="muted">pusty</span>'):'<span class="muted">nieznany</span>';
    return `<tr><td>Hasło ${n}</td><td>${st}</td>
    <td><input type="password" id="dp${dr.n}_${n}" maxlength="6" inputmode="numeric" placeholder="Kod" style="width:120px" autocomplete="new-password"></td>
    <td style="text-align:right;white-space:nowrap"><button class="btn" onclick="saveDoorPwd(${dr.n},${n},this)">Zapisz</button>
      <button class="iconbtn del" onclick="saveDoorPwd(${dr.n},${n},this,true)">Wyczyść</button></td></tr>`;}).join('');}).join('');
}
async function loadCodes(){if(codesBusy)return;codesBusy=true;
  $('#scBody').innerHTML='<tr><td colspan="4" class="muted"><span class="spin"></span> odczyt z kontrolera...</td></tr>';
  try{const d=await api('/api/codes');renderSuperCards(d.super_cards);renderPasswords(d.door_passwords,d.passwords_readable);}
  catch(e){$('#scBody').innerHTML='<tr><td colspan="4" class="muted">Błąd odczytu: '+esc(e.message)+'</td></tr>';renderPasswords(null,false);}
  finally{codesBusy=false;}}
async function saveSuperCard(n,b,clear){
  const v=clear?'':$('#sc'+n).value.trim();
  if(clear&&!confirm('Usunąć Super Card ze slotu '+n+'?'))return;
  if(!clear&&v&&!/^\d{1,19}$/.test(v)){toast('Numer karty: same cyfry (do 19)','err');return;}
  if(!clear&&!v){toast('Wpisz numer karty (do wyczyszczenia slotu służy „Usuń”)','err');return;}
  b.disabled=true;
  try{const d=await api('/api/supercard',form({slot:n,card:v}));renderSuperCards(d.super_cards);toast(d.msg,'ok');loadStatus();}
  catch(e){toast('Błąd: '+e.message,'err');b.disabled=false;}}
async function saveDoorPwd(door,n,b,clear){
  const v=clear?'':$('#dp'+door+'_'+n).value.trim();
  if(clear){if(!confirm('Wyczyścić hasło otwarcia drzwi #'+door+' w slocie '+n+'?'))return;}
  else if(!/^\d{1,6}$/.test(v)){toast('Hasło: od 1 do 6 cyfr','err');return;}
  b.disabled=true;
  try{const d=await api('/api/doorpassword',form({door,slot:n,pwd:v}));$('#dp'+door+'_'+n).value='';toast(d.msg,'ok');}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}
async function saveLang(){try{await api('/api/language',form({lang:$('#lang').value}));toast('Zmieniono język','ok');loadStatus();}catch(e){toast('Błąd: '+e.message,'err');}}
// Zegar kontrolera: odczytany RAZ (przy połączeniu i po synchronizacji), dalej liczony w przeglądarce
// od zegara systemowego (Date.now - odporne na uśpienie karty/komputera), bez odpytywania urządzenia.
let clockTimer=null,clockBase=null;
function parseClock(s){const m=/(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/.exec(s||'');
  return m?Date.UTC(+m[1],m[2]-1,+m[3],+m[4],+m[5],+m[6]):null;}
function fmtClock(ms){const d=new Date(ms),p=n=>String(n).padStart(2,'0');
  return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());}
function showClock(clock,server,how){
  const dev=parseClock(clock),srv=parseClock(server);
  clockBase=dev===null?null:{dev,at:Date.now(),clock,how:how||'przy połączeniu',drift:srv===null?null:Math.round((dev-srv)/1000)};
  if(!clockTimer)clockTimer=setInterval(renderClock,250);
  renderClock();
}
function renderClock(){
  const b=clockBase,v=b?fmtClock(b.dev+Date.now()-b.at):'—';
  document.querySelectorAll('.devclock').forEach(e=>{if(e.textContent!==v)e.textContent=v;});
  $('#connClock').hidden=!connected||!b;$('#clockBox').hidden=!connected;
  if(!b){$('#clockInfo').textContent=connected?'Nie udało się odczytać zegara kontrolera.':'';return;}
  const bad=b.drift!==null&&Math.abs(b.drift)>2;
  const diff=bad?'różni się od serwera panelu o '+Math.abs(b.drift)+' s ('+(b.drift<0?'spóźnia się':'spieszy się')+')':'';
  const info='Odczytano '+b.how+' ('+b.clock.slice(11)+'). Dalej czas jest liczony w przeglądarce - bez łączenia z kontrolerem.'+
    (b.drift===null?'':bad?' Uwaga: '+diff+'.':' Zgodny z czasem serwera panelu.');
  if($('#clockInfo').textContent!==info){$('#clockInfo').textContent=info;$('#clockInfo').style.color=bad?'var(--warn)':'';}
  const ci=$('#connClockInfo');ci.textContent=bad?'⚠️ '+diff:'';ci.style.color=bad?'var(--warn)':'';
}
function hideClock(){clearInterval(clockTimer);clockTimer=null;clockBase=null;renderClock();}
async function syncTime(b){if(b)b.disabled=true;
  toast('Synchronizuję czas... (może potrwać do minuty)','');
  try{const d=await api('/api/synctime',{method:'POST'});showClock(d.clock,d.server_time,'po synchronizacji');toast('Czas zsynchronizowany','ok');}
  catch(e){toast('Błąd: '+e.message,'err');}finally{if(b)b.disabled=false;}}
async function doReboot(){if(!confirm('Zrestartować urządzenie? Chwilowa przerwa w działaniu.'))return;
  try{await api('/api/reboot',{method:'POST'});toast('Restart wysłany','ok');}catch(e){toast('Błąd: '+e.message,'err');}}
async function saveAdmin(){
  const nn=$('#admNewName').value.trim(),np=$('#newPwd').value;
  if(!nn||!np){toast('Podaj nowy login i nowe hasło','err');return;}
  if(np!==$('#newPwd2').value){toast('Nowe hasła nie są takie same','err');return;}
  if(!confirm('Zmienić dane administratora na login „'+nn+'”?\nZapamiętaj nowe hasło - bez niego nie zalogujesz się do kontrolera.'))return;
  try{await api('/api/admin',form({old_name:$('#oldName').value,old_pwd:$('#oldPwd').value,new_name:nn,new_pwd:np}));
    toast('Zmieniono dane administratora','ok');
    $('#oldPwd').value='';$('#admNewName').value='';$('#newPwd').value='';$('#newPwd2').value='';
    await loadStatus();fillForms();}catch(e){toast('Błąd: '+e.message,'err');}}
async function factoryReset(b){
  if($('#resetConfirm').value.trim()!=='RESET'){toast('Wpisz RESET w polu potwierdzenia','err');return;}
  const s=lastStatus;
  if(!confirm('Zresetować kontroler „'+ctrlLabel(s)+'” ('+s.host+')?\n\nZostaną usunięte wszystkie karty, użytkownicy i hasła, a dane logowania zmienione na abc / 654321.\nTej operacji nie można cofnąć.'))return;
  b.disabled=true;$('#resetInfo').style.color='';
  $('#resetInfo').innerHTML='<span class="spin"></span> Trwa reset kontrolera... nie zamykaj panelu.';
  try{const d=await api('/api/factoryreset',{method:'POST'});
    $('#resetConfirm').value='';
    $('#resetInfo').style.color='var(--ok)';
    $('#resetInfo').innerHTML='Reset zakończony:<br>• '+d.done.map(esc).join('<br>• ');
    setConnected(d.active);loadSaved();fillForms();toast('Kontroler zresetowany','ok');
  }catch(e){
    $('#resetInfo').style.color='var(--err)';
    $('#resetInfo').textContent='Reset przerwany: '+e.message+'. Dane logowania zmieniane są na samym końcu - jeśli błąd wystąpił wcześniej, pozostały bez zmian.';
    toast('Błąd resetu: '+e.message,'err');loadStatus();
  }finally{b.disabled=false;}
}
async function saveNetwork(){if(!confirm('Zmienić IP na '+$('#netIp').value+'? Kontroler zrestartuje się, a panel połączy się z nowym adresem (ok. minuty).'))return;
  try{const d=await api('/api/network',form({ip:$('#netIp').value,gateway:$('#netGw').value}));
    toast(d.msg,'ok');if(d.active){setConnected(d.active);loadSaved();}
    [45,70,100].forEach(t=>setTimeout(loadStatus,t*1000));
  }catch(e){toast('Błąd: '+e.message,'err');}}

// --- powiadomienia ---
let nData=null;
const EH_DAY_KEYS=['Pn','Wt','Śr','Cz','Pt','So','Nd'];
async function notifyLoad(){try{nData=await api('/api/notify');renderNotify();}catch(e){toast('Błąd: '+e.message,'err');}}
function renderNotify(){const c=nData.settings,e=c.email,t=c.telegram,w=c.webhook,r=c.rules;
  $('#nEmailOn').checked=e.enabled;$('#nHost').value=e.host;$('#nPort').value=e.port;$('#nSec').value=e.security;$('#nUser').value=e.user;
  $('#nPass').value='';$('#nPass').placeholder=e.has_password?'zapisane - wpisz, aby zmienić':'';$('#nFrom').value=e.from;$('#nTo').value=e.to;
  $('#nTgOn').checked=t.enabled;$('#nTgToken').value='';$('#nTgToken').placeholder=t.has_token?'zapisany - wpisz, aby zmienić':'';$('#nTgChat').value=t.chat_id;
  $('#nWhOn').checked=w.enabled;$('#nWhUrl').value=w.url;$('#nCool').value=c.cooldown;
  const chk=(k)=>`<input type="checkbox" data-rule="${k}" ${r[k].on?'checked':''}>`;
  $('#nRules').innerHTML=[
    ['denied_repeat',`${chk('denied_repeat')} Ta sama karta odrzucona <input type="number" id="nDrCount" min="2" max="50" style="width:64px" value="${r.denied_repeat.count}"> razy w ciągu <input type="number" id="nDrMin" min="1" max="1440" style="width:64px" value="${r.denied_repeat.minutes}"> min`],
    ['unknown_card',`${chk('unknown_card')} Przyłożono kartę, której nie ma w kontrolerze`],
    ['blocked_card',`${chk('blocked_card')} Próba użycia karty zablokowanej w panelu`],
    ['after_hours',`${chk('after_hours')} Wejście poza godzinami pracy: <input type="time" id="nAhStart" value="${esc(r.after_hours.start)}"> – <input type="time" id="nAhEnd" value="${esc(r.after_hours.end)}"> w dni `+
      EH_DAY_KEYS.map((n,i)=>`<label class="small" style="margin-right:4px"><input type="checkbox" class="n-ah-day" ${r.after_hours.days[i]==='1'?'checked':''}>${n}</label>`).join('')],
    ['alarm',`${chk('alarm')} Alarm drzwi: otwarte zbyt długo, wymuszone otwarcie, pożar (zdarzenia alarmowe kontrolera)`],
    ['door_open',`${chk('door_open')} Drzwi otwarte dłużej niż czas ustawiony w zakładce <b>Drzwi</b> (czas liczy panel) i gdy zostaną zamknięte`],
    ['offline',`${chk('offline')} Zapisany kontroler nie odpowiada dłużej niż <input type="number" id="nOffMin" min="1" max="1440" style="width:64px" value="${r.offline.minutes}"> min (i gdy wróci)`],
  ].map(([k,h])=>`<tr><td><label class="small" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">${h}</label></td></tr>`).join('');
  $('#nLog').innerHTML=nData.log.length?nData.log.map(x=>`<tr><td style="white-space:nowrap">${esc(x.time)}</td><td><b>${esc(x.title)}</b><br><span class="muted small">${esc(x.text).replace(/\n/g,'<br>')}</span></td><td class="small ${/błąd|brak/.test(x.result)?'warn-t':''}">${esc(x.result)}</td></tr>`).join('')
    :'<tr><td colspan="3" class="muted">Jeszcze nic nie wysłano.</td></tr>';
}
function notifyCollect(){const on=k=>document.querySelector(`#nRules [data-rule="${k}"]`).checked;
  return {email:{enabled:$('#nEmailOn').checked,host:$('#nHost').value.trim(),port:$('#nPort').value||587,security:$('#nSec').value,user:$('#nUser').value.trim(),password:$('#nPass').value,from:$('#nFrom').value.trim(),to:$('#nTo').value.trim()},
    telegram:{enabled:$('#nTgOn').checked,token:$('#nTgToken').value.trim(),chat_id:$('#nTgChat').value.trim()},
    webhook:{enabled:$('#nWhOn').checked,url:$('#nWhUrl').value.trim()},cooldown:$('#nCool').value||0,
    rules:{denied_repeat:{on:on('denied_repeat'),count:$('#nDrCount').value,minutes:$('#nDrMin').value},unknown_card:{on:on('unknown_card')},blocked_card:{on:on('blocked_card')},
      after_hours:{on:on('after_hours'),start:$('#nAhStart').value,end:$('#nAhEnd').value,days:[...document.querySelectorAll('.n-ah-day')].map(c=>c.checked?'1':'0').join('')},
      alarm:{on:on('alarm')},door_open:{on:on('door_open')},offline:{on:on('offline'),minutes:$('#nOffMin').value}}};}
async function notifySave(b){b.disabled=true;
  try{nData=await api('/api/notify',form({settings:JSON.stringify(notifyCollect())}));renderNotify();toast('Zapisano ustawienia powiadomień','ok');return true;}
  catch(e){toast('Błąd: '+e.message,'err');return false;}finally{b.disabled=false;}}
async function notifyTest(b){if(!await notifySave(b))return;b.disabled=true;toast('Wysyłanie wiadomości testowej...');
  try{const r=await api('/api/notify/test',{method:'POST'});toast(r.msg,/błąd|brak/.test(r.msg)?'err':'ok');notifyLoad();}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}

// --- dziennik działań ---
let auditPage=1;
async function auditLoad(page){if(page<1)return;
  const q=new URLSearchParams({page,login:$('#aLogin').value,q:$('#aQ').value.trim(),from:$('#aFrom').value,to:$('#aTo').value,errors:$('#aErr').checked?'1':''});
  try{const d=await api('/api/audit?'+q);if(page>d.pages&&page>1)return;auditPage=d.page;
    setOptions($('#aLogin'),'<option value="">Wszyscy</option>'+d.logins.map(l=>`<option value="${esc(l)}">${esc(l)}</option>`).join(''));
    $('#aInfo').textContent='Strona '+d.page+' z '+d.pages+' · wpisów: '+d.total;
    $('#aBody').innerHTML=d.rows.length?d.rows.map(r=>`<tr class="${r.ok?'':'deny'}"><td style="white-space:nowrap">${esc(r.time)}</td><td><b>${esc(r.login)}</b></td><td class="muted small">${esc(r.ip)}</td>
      <td class="small">${esc(r.ctrl)||'<span class="muted">—</span>'}</td><td>${esc(r.action)}${r.ok?'':'<br><span class="warn-t small">błąd: '+esc(r.error)+'</span>'}</td><td class="small">${esc(r.details)}</td></tr>`).join('')
      :'<tr><td colspan="6" class="muted">Brak wpisów.</td></tr>';}
  catch(e){$('#aBody').innerHTML='<tr><td colspan="6" class="muted">'+esc(e.message)+'</td></tr>';}}

// --- konta panelu ---
let accData=null;
async function accLoad(){try{accData=await api('/api/panel/users');
  $('#accBody').innerHTML=accData.users.map(u=>`<tr><td><b>${esc(u.login)}</b>${u.me?' <span class="pill mdl">to Ty</span>':''}</td><td>${esc(u.name)}</td>
    <td>${esc(accData.roles[u.role]||u.role)}</td><td>${u.active?'<span class="pill on">aktywne</span>':'<span class="pill off">wyłączone</span>'}</td>
    <td class="small">${esc(u.last_login)||'<span class="muted">nigdy</span>'}</td><td class="small">${u.sessions||'—'}</td>
    <td class="act"><button class="iconbtn" onclick="accEdit(${u.id})">Edytuj</button>${u.me?'':`<button class="iconbtn del" onclick="accDelete(${u.id})">Usuń</button>`}</td></tr>`).join('');}
  catch(e){$('#accBody').innerHTML='<tr><td colspan="7" class="muted">'+esc(e.message)+'</td></tr>';}}
function accEdit(id){const u=id?accData.users.find(x=>x.id===id):null;const dlg=$('#accDlg');
  $('#accDlgTitle').textContent=u?'Konto: '+u.login:'Nowe konto panelu';
  $('#accLogin').value=u?u.login:'';$('#accName').value=u?u.name:'';$('#accRole').value=u?u.role:'operator';$('#accPwd').value='';
  $('#accPwd').required=!u;$('#accPwdLbl').textContent=u?'Nowe hasło (puste = bez zmiany)':'Hasło (co najmniej 8 znaków)';$('#accActive').checked=u?!!u.active:true;
  dlg.returnValue='';
  dlg.onclose=async()=>{if(dlg.returnValue!=='ok')return;
    try{await api('/api/panel/users/save',form({id:u?u.id:'',login:$('#accLogin').value.trim(),name:$('#accName').value.trim(),role:$('#accRole').value,pwd:$('#accPwd').value,active:$('#accActive').checked?'1':'0'}));
      toast('Zapisano konto','ok');accLoad();}catch(e){toast('Błąd: '+e.message,'err');}};
  dlg.showModal();}
async function accDelete(id){const u=accData.users.find(x=>x.id===id);if(!u||!confirm('Usunąć konto „'+u.login+'”? Jego sesje zostaną wylogowane.'))return;
  try{await api('/api/panel/users/delete',form({id}));toast('Usunięto konto','ok');accLoad();}catch(e){toast('Błąd: '+e.message,'err');}}

// --- ustawienia panelu: zegary i kopie ---
let mData=null;
async function maintLoad(){try{mData=await api('/api/maintenance');renderMaint();}catch(e){toast('Błąd: '+e.message,'err');}}
function renderMaint(){const c=mData.settings;
  $('#mClock').checked=c.clock_sync;$('#mDrift').value=c.clock_max_drift;$('#mHours').value=c.clock_check_hours;
  $('#mBackup').checked=c.backup;$('#mTime').value=c.backup_time;$('#mKeep').value=c.backup_keep;
  $('#mClocks').innerHTML=mData.clocks.length?mData.clocks.map(x=>`<div>🕒 <b>${esc(x.name)}</b>: ${esc(x.result)}${x.drift!==null&&x.drift!==undefined?' <span class="muted">(różnica '+x.drift+' s)</span>':''}${x.at?' <span class="muted">· '+esc(x.at)+'</span>':''}</div>`).join('')
    :'<span class="muted">Brak połączonych kontrolerów.</span>';
  const b=mData.backup;$('#mBackupInfo').innerHTML=b.last&&b.last!=='-'?'<span class="muted">Ostatnia: '+esc(b.last)+(b.result?' - '+esc(b.result):'')+'</span>':'';
  $('#mDir').textContent='Katalog kopii: '+mData.backup_dir+'. Kopie zawierają numery kart i nazwiska - chroń ten katalog; najlepiej kopiuj go też na inny dysk.';
  $('#mFiles').innerHTML=mData.files.length?mData.files.map(f=>`<tr><td><a href="/api/backups/file?name=${encodeURIComponent(f.name)}">${esc(f.name)}</a></td><td class="small muted">${esc(f.time)}</td><td class="small muted">${Math.max(1,Math.round(f.size/1024))} KB</td></tr>`).join('')
    :'<tr><td class="muted">Brak kopii.</td></tr>';
  $('#mTls').innerHTML=location.protocol==='https:'?'<span class="ok-t">✅ Ta strona jest otwarta po HTTPS.</span>':'<span class="warn-t">⚠️ Ta strona jest otwarta po HTTP'+(/^(127\.|localhost)/.test(location.hostname)?' (na tym samym komputerze - ruch nie wychodzi do sieci).':' - hasło do panelu idzie w sieci otwartym tekstem.')+'</span>';
}
async function maintSave(b){b.disabled=true;
  try{mData=await api('/api/maintenance',form({settings:JSON.stringify({clock_sync:$('#mClock').checked,clock_max_drift:$('#mDrift').value,clock_check_hours:$('#mHours').value,
    backup:$('#mBackup').checked,backup_time:$('#mTime').value,backup_keep:$('#mKeep').value})}));renderMaint();toast('Zapisano ustawienia','ok');}
  catch(e){toast('Błąd: '+e.message,'err');}finally{b.disabled=false;}}
async function maintBackup(b){b.disabled=true;$('#mBackupInfo').innerHTML='<span class="spin"></span> Tworzenie kopii...';
  try{const r=await api('/api/maintenance/backup',{method:'POST'});toast(r.msg,r.ok?'ok':'err');maintLoad();}
  catch(e){toast('Błąd: '+e.message,'err');$('#mBackupInfo').textContent='';}finally{b.disabled=false;}}

// --- ustawienia panelu: czyszczenie logów ---
let lgData=null,lgSeq=0;
async function lgLoad(){try{lgData=await api('/api/logs');lgRender();}catch(e){toast('Błąd: '+e.message,'err');}}
function lgRender(){const was=new Set([...document.querySelectorAll('#lgKinds input:checked')].map(x=>x.value));
  $('#lgKinds').innerHTML=lgData.kinds.map(k=>`<tr><td><input type="checkbox" value="${k.id}" onchange="lgPreview()"${was.has(k.id)?' checked':''}></td><td>${esc(k.label)}</td><td>${k.count}</td><td class="small muted">${esc(k.oldest)}</td><td class="small muted">${esc(k.newest)}</td></tr>`).join('');
  const sel=$('#lgCtrl'),cur=sel.value;
  sel.innerHTML='<option value="">Wszystkie kontrolery</option>'+lgData.ctrls.map(c=>`<option value="${esc(c.key)}">${esc(c.name)}</option>`).join('');
  if(lgData.ctrls.some(c=>c.key===cur))sel.value=cur;
  $('#lgCleared').innerHTML=lgData.cleared.map(c=>`<div class="muted">🧹 ${esc(c.name)}: log przejść wyczyszczony do ${esc(c.to)} - starszych wpisów panel nie pobiera z kontrolera</div>`).join('');
  lgScope();}
function lgParams(){return {kinds:[...document.querySelectorAll('#lgKinds input:checked')].map(x=>x.value).join(','),
  ctrl:$('#lgCtrl').value,before:$('#lgMode').value==='all'?'':$('#lgBefore').value};}
function lgScope(){$('#lgDateFld').hidden=$('#lgMode').value==='all';lgPreview();}
async function lgPreview(){const p=lgParams(),seq=++lgSeq;$('#lgBtn').disabled=true;
  if(!p.kinds){$('#lgInfo').innerHTML='<span class="muted">Zaznacz logi do wyczyszczenia.</span>';return;}
  if($('#lgMode').value==='before'&&!p.before){$('#lgInfo').innerHTML='<span class="muted">Wybierz datę.</span>';return;}
  try{const r=await api('/api/logs/preview',form(p));if(seq!==lgSeq)return;
    $('#lgInfo').innerHTML=r.total?'<span class="warn-t">Do usunięcia: '+r.rows.map(x=>esc(x.label)+' '+x.count).join(', ')+'</span>':'<span class="muted">Brak wpisów w tym zakresie.</span>';
    $('#lgBtn').disabled=!r.total;$('#lgBtn').dataset.total=r.total;}
  catch(e){if(seq===lgSeq)$('#lgInfo').innerHTML='<span class="err-t">'+esc(e.message)+'</span>';}}
async function lgClear(b){const p=lgParams();
  const what=[...document.querySelectorAll('#lgKinds input:checked')].map(x=>x.closest('tr').children[1].textContent).join(', ');
  const scope=p.before?'sprzed '+p.before:'CAŁY log';
  if(!confirm('Usunąć '+b.dataset.total+' wpisów ('+what+', '+scope+')?\n\nTych wpisów panel nie pobierze ponownie z kontrolera. Przywrócić je można tylko z kopii bazy zapisanej przed czyszczeniem.'))return;
  b.disabled=true;$('#lgInfo').innerHTML='<span class="spin"></span> Czyszczenie...';
  try{const r=await api('/api/logs/clear',form(p));toast(r.msg,'ok');lgData=r.state;lgRender();maintLoad();}
  catch(e){toast('Błąd: '+e.message,'err');lgPreview();}}

// --- start ---
function syncHeaderHeight(){document.documentElement.style.setProperty('--hh',document.querySelector('header').offsetHeight+'px');}
if(window.ResizeObserver)new ResizeObserver(syncHeaderHeight).observe(document.querySelector('header'));else syncHeaderHeight();
async function init(){
  try{authInfo=await (await fetch('/api/auth')).json();}catch(e){authInfo={};}
  applyMode();
  if(!authInfo.user){showAuth();return;}
  me=authInfo.user;appStarted=true;document.body.classList.remove('locked');$('#authView').hidden=true;renderMe();applyVisibility();
  if(can('admin'))try{const d=await api('/api/subnet');$('#subnet').value=d.subnet;}catch(e){}
  try{const a=await api('/api/active');connList=a.connected||[];renderSwitch();
    if(a.active){connected=true;setConnected(a.active);if(can('operator'))autoTick();livePoll();
      // zapamiętany w panelu odczyt zegara może być stary - jeden świeży odczyt przy otwarciu strony
      const h=location.hash.slice(1),t=h&&document.querySelector('nav button[data-tab="'+h.replace(/\W/g,'')+'"]');
      if(t&&!t.hidden&&h!=='find')goTab(h);else goTab('dash');
      try{const s=await api('/api/status');renderStatus(s);renderConn(s);showClock(s.clock,s.server_time);}catch(e){}}
    else{
      $('#scanUser').value=a.default_user||'admin';$('#scanPwd').value='admin';
      $('#directIp').value=a.default_host||'';$('#directUser').value=a.default_user||'admin';$('#directPwd').value='admin';
      const h=location.hash.slice(1),t=h&&document.querySelector('nav button[data-tab="'+h.replace(/\W/g,'')+'"]');
      if(t&&!t.hidden)goTab(h);
      offlineWaitForConnect();
    }
    loadSaved();
  }catch(e){}
  setInterval(()=>{if(connected&&!document.hidden)loadStatus();},20000);
  setInterval(()=>{if(!document.hidden&&$('#find').classList.contains('active'))loadSaved();},10000);
  setInterval(()=>{if(connected)livePoll();},2500);
  setInterval(()=>{if(connected&&!document.hidden&&$('#dash').classList.contains('active'))loadPresence();},20000);
  const y=new Date().getFullYear();$('#ehPlYear').innerHTML=[y,y+1].map(v=>`<option>${v}</option>`).join('');
  try{$('#liveNotif').checked=localStorage.getItem('acbLiveNotif')==='1'&&window.Notification&&Notification.permission==='granted';}catch(e){}
}
init();
</script></body></html>"""


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    # Na Windows SO_REUSEADDR pozwala drugiemu procesowi zająć ten sam port - wtedy dwie
    # kopie panelu działałyby naraz i łączyły się z kontrolerem z dwóch miejsc.
    allow_reuse_address = os.name != "nt"
    tls = None

    def finish_request(self, request, client_address):
        # uzgadnianie TLS w wątku zapytania - wolny klient nie blokuje przyjmowania kolejnych połączeń
        if self.tls is not None:
            try:
                request.settimeout(15)
                request = self.tls.wrap_socket(request, server_side=True)
                request.settimeout(None)
            except (OSError, ssl.SSLError):
                return
        super().finish_request(request, client_address)


def _tls_context():
    if not TLS_CERT:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY or None)
    return ctx


def _running_panel(host, port):
    """Czy pod host:port działa już ten panel (np. program uruchomiony drugi raz)."""
    try:
        h = "127.0.0.1" if host in ("0.0.0.0", "") else host
        c = (http.client.HTTPSConnection(h, port, timeout=2, context=ssl._create_unverified_context()) if TLS_CERT
             else http.client.HTTPConnection(h, port, timeout=2))
        c.request("GET", "/api/version")
        r = c.getresponse()
        return r.status == 200 and json.loads(r.read()).get("app") == "acb-panel"
    except (OSError, ValueError, http.client.HTTPException):
        return False


def _open_browser(url):
    if OPEN_BROWSER:
        try:
            webbrowser.open(url)
        except Exception:
            pass


def main():
    try:
        sys.stdout.reconfigure(errors="replace", line_buffering=True)   # konsola bez UTF-8 nie wywróci programu
    except (AttributeError, ValueError):
        pass
    print(f"Spreest - Panel ACB  v{APP_VERSION}  (tryb {PANEL_MODE})")
    print("-" * 52)
    try:
        tls = _tls_context()
    except (OSError, ssl.SSLError) as e:
        print(f"Nie udało się wczytać certyfikatu HTTPS (ACS_TLS_CERT / ACS_TLS_KEY): {e}")
        sys.exit(1)
    scheme = "https" if tls else "http"
    server = None
    for port in range(LISTEN_PORT, LISTEN_PORT + 20):
        if _running_panel(LISTEN_HOST, port):
            url = f"{scheme}://{'127.0.0.1' if LISTEN_HOST in ('0.0.0.0', '') else LISTEN_HOST}:{port}"
            print(f"Panel już działa: {url} - otwieram przeglądarkę.")
            _open_browser(url)
            return
        try:
            server = PanelServer((LISTEN_HOST, port), Handler)
            break
        except OSError:
            continue                                   # port zajęty przez inny program
    if server is None:
        print(f"Nie znaleziono wolnego portu ({LISTEN_PORT}-{LISTEN_PORT + 19}).")
        sys.exit(1)
    server.tls = tls
    _SETUP.update(port=server.server_address[1], scheme=scheme)
    host = "127.0.0.1" if LISTEN_HOST in ("0.0.0.0", "") else LISTEN_HOST
    url = f"{scheme}://{host}:{server.server_address[1]}"
    setup_prepare()
    print(f"Panel działa pod adresem:  {url}")
    print(f"Dane (zapisane kontrolery): {DATA_DIR}")
    if OFFLINE:
        print()
        print("TRYB OFFLINE - panel do pracy doraźnej (np. wyciąg czasu pracy).")
        print("  Po starcie łączy się z zapisanym kontrolerem i pobiera log przejść.")
        print("  Nie działają funkcje wymagające panelu włączonego bez przerwy:")
        for why in OFFLINE_OFF.values():
            print(f"    - {why}")
        print("  Potrzebujesz ich? Uruchom panel w trybie online (bez ACS_MODE=offline).")
    if AUTH_DISABLED:
        print("Logowanie do panelu WYŁĄCZONE (ACS_AUTH=0) - każdy na tym komputerze ma pełny dostęp.")
    elif os.environ.get("ACS_AUTH", "") == "0":
        print("ACS_AUTH=0 działa tylko przy ACS_BIND=127.0.0.1 - logowanie pozostaje włączone.")
    if _SETUP["code"]:
        print()
        print("PIERWSZE URUCHOMIENIE: utwórz konto administratora panelu w przeglądarce.")
        print(f"Z innego komputera w sieci potrzebny jest kod: {_SETUP['code']}")
        print(f"(kod jest też w pliku {SETUP_FILE})")
    if not tls and LISTEN_HOST not in ("127.0.0.1", "localhost", "::1") and not TRUST_PROXY:
        print("Uwaga: panel jest dostępny w sieci po HTTP - hasła do panelu idą otwartym tekstem.")
        print("       Ustaw ACS_TLS_CERT i ACS_TLS_KEY (HTTPS) albo postaw panel za serwerem HTTPS.")
    print()
    print("Przeglądarka otworzy się sama. Jeśli nie - wpisz powyższy adres.")
    print("NIE ZAMYKAJ tego okna - zamknięcie wyłącza panel.")
    print("-" * 52)
    threading.Thread(target=_online_loop, name="online-check", daemon=True).start()
    if not OFFLINE:                       # powiadomienia wymagają panelu działającego bez przerwy
        threading.Thread(target=_notify_loop, name="notify", daemon=True).start()
    threading.Thread(target=_maintenance_loop, name="maintenance", daemon=True).start()
    threading.Timer(0.8, _open_browser, (url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Zatrzymano panel.")
    finally:
        server.server_close()
        for g in list(_GATES.values()):
            g.close()


if __name__ == "__main__":
    main()
