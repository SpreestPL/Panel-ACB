#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buduje paczki do rozesłania klientom (np. przez Google Drive):

    dist/ACB-Panel-<wersja>-Windows.zip
    dist/ACB-Panel-<wersja>-macOS.zip
    dist/ACB-Panel-<wersja>-Linux.zip
    dist/ACB-Panel-Offline-<wersja>-{Windows,macOS,Linux}.zip

Każda paczka zawiera panel, przenośnego Pythona dla danego systemu (python-build-standalone,
bez instalacji), plik startowy do dwukliku i instrukcję. Panel używa tylko biblioteki
standardowej, więc nic więcej nie jest potrzebne. Budowanie działa na dowolnym systemie
z Pythonem 3.8+ i dostępem do GitHuba (nic nie jest kompilowane).

Dwa warianty tej samej aplikacji (ten sam acs_panel.py, różnica to ACS_MODE w pliku startowym):
  online  - panel połączony z kontrolerem bez przerwy, wszystkie funkcje (paczka dla klienta,
            który ma komputer albo serwer włączony całą dobę);
  offline - panel uruchamiany doraźnie, np. po wyciąg czasu pracy; nie ma funkcji wymagających
            ciągłego połączenia (zdarzenia na żywo, powiadomienia, ostrzeżenie o otwartych
            drzwiach, godziny wejścia w kilku zmianach). Rozpakowuje się do osobnego folderu,
            więc może leżeć obok wersji online.

    python3 packaging/build_release.py                    # online, wszystkie systemy
    python3 packaging/build_release.py linux              # online, tylko wybrane
    python3 packaging/build_release.py --offline          # offline, wszystkie systemy
    python3 packaging/build_release.py --offline linux    # offline, tylko wybrane
    python3 packaging/build_release.py --all-modes        # oba warianty
"""

import hashlib
import os
import re
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(ROOT, "packaging")
CACHE = os.path.join(HERE, ".cache")
DIST = os.path.join(ROOT, "dist")

# python-build-standalone: wydanie i wersja CPythona (aktualizacja = zmiana tych dwóch linii)
PBS_RELEASE = "20260901"
PBS_PYTHON = "3.13.15"
PBS_URL = "https://github.com/astral-sh/python-build-standalone/releases/download/" + PBS_RELEASE

TARGETS = {
    "windows": {"label": "Windows", "runtimes": {"windows-x64": "x86_64-pc-windows-msvc"}},
    "macos": {"label": "macOS", "runtimes": {"macos-arm64": "aarch64-apple-darwin",
                                             "macos-x64": "x86_64-apple-darwin"}},
    "linux": {"label": "Linux", "runtimes": {"linux-x64": "x86_64-unknown-linux-gnu",
                                             "linux-arm64": "aarch64-unknown-linux-gnu"}},
}

# zbędne dla panelu części Pythona (GUI, pip, IDLE, nagłówki) - ścieżki względem katalogu runtime
TRIM_DIRS = ["include", "share", "libs", "tcl", "Scripts",
             "Lib/idlelib", "Lib/tkinter", "Lib/turtledemo", "Lib/ensurepip", "Lib/site-packages",
             "lib/pkgconfig", "lib/itcl4.2.4", "lib/thread2.8.9", "lib/tcl9", "lib/tcl8", "lib/tk8.6",
             "lib/tcl8.6", "lib/tk9.0"]
TRIM_LIB = ["idlelib", "tkinter", "turtledemo", "ensurepip", "site-packages", "lib2to3"]
TRIM_FILE_RE = re.compile(r"(^|/)(_tkinter[^/]*|tcl\d+t?\.dll|tk\d+t?\.dll|libtcl[^/]*|libtk[^/]*|"
                          r"idle3?[^/]*|pip3?[^/]*|pydoc3?[^/]*|python3?(\.\d+)?-config)$")

TOP = "ACB Panel"          # nazwa folderu po rozpakowaniu (wariant offline dokłada sufiks)

ONLINE_FEATURES = """Program do obsługi sieciowych kontrolerów dostępu ACB-001, ACB-002 i ACB-004 - także kilku naraz:
karty i użytkownicy (uprawnienia do drzwi, ważność, blokady), log przejść, ruch na żywo
i lista osób w budynku, godziny wejścia działów z dniami wolnymi, czas pracy (normy,
nadgodziny, spóźnienia, korekty, karta miesięczna do druku), powiadomienia (e-mail,
Telegram, webhook), konta panelu z rolami i dziennikiem działań, automatyczne kopie.
Nie wymaga instalacji ani dostępu do internetu."""

OFFLINE_FEATURES = """Program do obsługi sieciowych kontrolerów dostępu ACB-001, ACB-002 i ACB-004 - także kilku naraz:
karty i użytkownicy (uprawnienia do drzwi, ważność, blokady), log przejść, lista osób
w budynku, godziny wejścia działów (jedna zmiana) z dniami wolnymi, czas pracy (normy,
nadgodziny, spóźnienia, korekty, karta miesięczna do druku), konta panelu z rolami
i dziennikiem działań, kopie zapasowe.
Nie wymaga instalacji ani dostępu do internetu."""

# warianty aplikacji - ten sam kod panelu, inny plik startowy (ACS_MODE) i inna instrukcja
VARIANTS = {
    "online": {
        "name": "ACB-Panel", "top": TOP, "start": "Uruchom panel ACB", "start_linux": "uruchom-panel-acb.sh",
        "title": "", "title_bat": "", "env_sh": "", "env_bat": "", "info": "",
        "features": ONLINE_FEATURES,
    },
    "offline": {
        "name": "ACB-Panel-Offline", "top": TOP + " Offline", "start": "Uruchom panel ACB (offline)",
        "start_linux": "uruchom-panel-acb-offline.sh",
        "title": "\n***  W E R S J A   O F F L I N E  - do pracy doraźnej (opis niżej)  ***",
        "title_bat": " (offline)", "features": OFFLINE_FEATURES,
        "env_sh": "export ACS_MODE=offline\n", "env_bat": 'set "ACS_MODE=offline"\n',
        "info": """
TRYB OFFLINE - CO TO ZNACZY
Ta wersja jest do pracy doraźnej: uruchamiasz ją wtedy, gdy czegoś potrzebujesz
(np. raz w miesiącu po wyciąg czasu pracy), a po skończonej pracy zamykasz.
Po uruchomieniu panel sam łączy się z zapisanym kontrolerem, pobiera log przejść
i trzyma połączenie aż do zamknięcia programu.

Działa: czas pracy (raporty, eksport CSV, karta miesięczna do druku), log przejść,
pracownicy i karty (dodawanie, ważność, blokady, działy), lista osób w środku
i lista ewakuacyjna, otwieranie drzwi, ustawienia kontrolera, kopie zapasowe,
konta panelu i dziennik działań, godziny wejścia w jednej zmianie.

NIE działa w tej wersji (te funkcje wymagają panelu włączonego BEZ PRZERWY):
  - podgląd zdarzeń na żywo,
  - powiadomienia (e-mail, Telegram, webhook),
  - ostrzeżenie o drzwiach otwartych zbyt długo,
  - godziny wejścia w kilku zmianach, czyli różne godziny dla różnych działów
    (jedna zmiana - te same godziny dla wszystkich działów z kartami - działa,
    bo zapisuje się w samym kontrolerze i obowiązuje także po zamknięciu panelu).

Potrzebujesz tych funkcji? Poproś o wersję online i uruchamiaj ją na komputerze,
który jest włączony cały czas. Obie wersje korzystają z tych samych danych na tym
komputerze, więc można je wymienić bez utraty logu, pracowników i ustawień.
""",
    },
}


def app_version():
    src = open(os.path.join(ROOT, "acs_panel.py"), encoding="utf-8").read()
    return re.search(r'^APP_VERSION = "([^"]+)"', src, re.M).group(1)


def fetch(url, dest):
    if os.path.exists(dest):
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print("  pobieram", url.rsplit("/", 1)[1])
    with urllib.request.urlopen(url) as r, open(dest + ".part", "wb") as f:
        shutil.copyfileobj(r, f)
    os.replace(dest + ".part", dest)
    return dest


def runtime_archive(triple):
    name = f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-{triple}-install_only_stripped.tar.gz"
    sums = open(fetch(PBS_URL + "/SHA256SUMS", os.path.join(CACHE, f"SHA256SUMS-{PBS_RELEASE}"))).read()
    m = re.search(r"^([0-9a-f]{64})\s+\*?" + re.escape(name) + r"$", sums, re.M)
    if not m:
        sys.exit(f"Brak {name} w SHA256SUMS wydania {PBS_RELEASE}")
    path = fetch(PBS_URL + "/" + urllib.request.quote(name), os.path.join(CACHE, name))
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if h != m.group(1):
        os.remove(path)
        sys.exit(f"Zła suma SHA256 pliku {name} - usunięto, uruchom ponownie")
    return path


def trimmed(rel):
    """rel - ścieżka wewnątrz archiwum bez prefiksu 'python/'."""
    if any(rel == d or rel.startswith(d + "/") for d in TRIM_DIRS):
        return True
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == "lib" and parts[1].startswith("python3") and parts[2] in TRIM_LIB:
        return True
    if "__pycache__" in parts or (parts[-1].startswith("test_") and "/test" in rel):
        return True
    if len(parts) >= 2 and parts[-2] in ("test", "tests") and parts[0] in ("Lib", "lib"):
        return True
    return bool(TRIM_FILE_RE.search(rel)) and not rel.endswith(".py")


def add_file(z, arcname, data, mode=0o644):
    zi = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
    zi.create_system = 3                              # Unix - uprawnienia są respektowane
    zi.external_attr = (stat.S_IFREG | mode) << 16
    zi.compress_type = zipfile.ZIP_DEFLATED
    z.writestr(zi, data, compresslevel=9)


def add_symlink(z, arcname, target):
    zi = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
    zi.create_system = 3
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
    z.writestr(zi, target)


def add_runtime(z, key, triple, top=TOP):
    n_files = 0
    with tarfile.open(runtime_archive(triple)) as t:
        for m in t.getmembers():
            if not m.name.startswith("python/") or m.isdir():
                continue
            rel = m.name[len("python/"):]
            if trimmed(rel):
                continue
            arc = f"{top}/runtime/{key}/{rel}"
            if m.issym():
                add_symlink(z, arc, m.linkname)
            elif m.isfile():
                add_file(z, arc, t.extractfile(m).read(), 0o755 if m.mode & 0o111 else 0o644)
                n_files += 1
    return n_files


def template(name):
    return open(os.path.join(HERE, "templates", name), encoding="utf-8").read()


def fill(text, var, version="", bat=False, start=""):
    """Podstawia znaczniki wariantu w szablonie. `bat` - plik .bat ma własny sufiks tytułu okna,
    `start` - nazwa pliku startowego, którą w instrukcji widzi klient (jest inna w wersji offline)."""
    return (text.replace("{{VERSION}}", version)
                .replace("{{TOP}}", var["top"])
                .replace("{{START}}", start)
                .replace("{{MODE_TITLE_BAT}}", var["title_bat"])
                .replace("{{MODE_TITLE}}", var["title"])
                .replace("{{MODE_INFO}}", var["info"])
                .replace("{{MODE_FEATURES}}", var["features"])
                .replace("{{MODE_ENV}}", var["env_bat"] if bat else var["env_sh"]))


def build(target, version, mode="online"):
    cfg, var = TARGETS[target], VARIANTS[mode]
    top = var["top"]
    out = os.path.join(DIST, f"{var['name']}-{version}-{cfg['label']}.zip")
    tmp = out + ".part"
    print(f"{cfg['label']} ({mode}):")
    with zipfile.ZipFile(tmp, "w") as z:
        add_file(z, f"{top}/app/acs_panel.py", open(os.path.join(ROOT, "acs_panel.py"), "rb").read())
        start = {"windows": f"{var['start']}.bat", "macos": f"{var['start']}.command"}.get(target, var["start_linux"])
        text = fill(template(f"INSTRUKCJA-{cfg['label']}.txt"), var, version, start=start)
        # Notatnik i edytory na Windows/macOS lepiej znoszą CRLF / BOM
        if target == "windows":
            add_file(z, f"{top}/INSTRUKCJA.txt", b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("utf-8"))
        else:
            add_file(z, f"{top}/INSTRUKCJA.txt", text.encode("utf-8"))
        if target == "windows":
            bat = fill(template("start-windows.bat"), var, bat=True).replace("\n", "\r\n")
            add_file(z, f"{top}/{var['start']}.bat", bat.encode("utf-8"))
        elif target == "macos":
            add_file(z, f"{top}/{var['start']}.command", fill(template("start-macos.command"), var).encode(), 0o755)
        else:
            add_file(z, f"{top}/{var['start_linux']}", fill(template("start-linux.sh"), var).encode(), 0o755)
        for key, triple in cfg["runtimes"].items():
            print(f"  runtime {key}: {add_runtime(z, key, triple, top)} plików")
    os.replace(tmp, out)
    print(f"  -> {os.path.relpath(out, ROOT)} ({os.path.getsize(out) / 1e6:.1f} MB)")
    return out


def main():
    args = sys.argv[1:]
    modes = ["online"]
    if "--all-modes" in args:
        modes = ["online", "offline"]
    elif "--offline" in args:
        modes = ["offline"]
    targets = [a for a in args if not a.startswith("--")] or list(TARGETS)
    bad = [t for t in targets if t not in TARGETS]
    if bad:
        sys.exit(f"Nieznany system: {', '.join(bad)} (dostępne: {', '.join(TARGETS)})")
    os.makedirs(DIST, exist_ok=True)
    version = app_version()
    print(f"Spreest - Panel ACB v{version}, Python {PBS_PYTHON} ({PBS_RELEASE}), warianty: {', '.join(modes)}")
    for mode in modes:
        for t in targets:
            build(t, version, mode)


if __name__ == "__main__":
    main()
