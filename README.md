# Spreest - Panel ACB

Uniwersalny program do wyszukiwania i obsługi sieciowych kontrolerów dostępu
rodziny **ACB** (kontrolery Wiegand z wbudowanym web-serwerem „Web Controller",
komunikacja po HTTP/TCP-IP) oferowanych przez Spreest.

Program działa jako lokalny serwer-pośrednik: udostępnia czysty interfejs WWW
i tłumaczy kliknięcia na natywne zapytania kontrolera (`ACT_ID_*`). Dzięki temu
omija ograniczenia oryginalnego interfejsu (czysty HTTP w LAN, brak CORS).

## Wymagania

- Python 3.8+ (panel nie wymaga zewnętrznych bibliotek)
- Biblioteka `requests` — tylko dla skryptu diagnostycznego `acs_diag.py`

> **Uwaga:** kontroler obsługuje tylko 11 połączeń TCP od uruchomienia — 12. go
> restartuje (szczegóły: [docs/PROTOCOL.md](docs/PROTOCOL.md)). Panel używa jednego
> trwałego połączenia. Nie uruchamiaj równolegle innych narzędzi łączących się
> z kontrolerem (np. `acs_diag.py`, skanerów portów) — każde zużywa te miejsca.

## Uruchomienie

```bash
python3 acs_panel.py
```

Przeglądarka otworzy się sama na **http://127.0.0.1:8088** (jeśli port jest zajęty — na kolejnym wolnym;
drugie uruchomienie tylko otwiera przeglądarkę na już działającym panelu).

**Od 2.0.0 panel wymaga logowania.** Przy pierwszym uruchomieniu (brak kont) przeglądarka pokazuje formularz
utworzenia konta administratora panelu. Na komputerze z panelem (połączenie z 127.0.0.1) kod nie jest potrzebny;
z innego komputera trzeba podać kod wypisany w konsoli panelu i zapisany w `kod-pierwszego-logowania.txt`
w katalogu danych (plik znika po utworzeniu konta). Zamiast tego można ustawić `ACS_ADMIN_LOGIN` i `ACS_ADMIN_PASSWORD`.
Od 2.0.1 formularz z innego komputera pokazuje, gdzie dokładnie jest kod: pełną ścieżkę pliku z instrukcją otwarcia dla
systemu, na którym działa panel (Eksplorator / Finder / terminal), okno konsoli albo — gdy panel działa w tle na Linuksie —
ścieżkę jego logu (z `/proc/self/fd/1`), a przy `ACS_BIND=0.0.0.0` adres `127.0.0.1`, pod którym kod nie jest potrzebny.
Kod zmienia się przy każdym uruchomieniu panelu, dopóki nie powstanie pierwsze konto. Ścieżki są pokazywane tylko,
gdy w panelu nie ma jeszcze żadnego konta.

Konfiguracja przez zmienne środowiskowe (opcjonalnie):

| Zmienna | Znaczenie | Domyślnie |
|---|---|---|
| `ACS_MODE` | tryb pracy panelu: `online` (stale połączony, wszystkie funkcje) albo `offline` (uruchamiany doraźnie — zob. „Tryb online i tryb offline”) | `online` |
| `ACS_HOST` | IP podpowiadane przy połączeniu bezpośrednim | puste |
| `ACS_USER` / `ACS_PWD` | domyślne dane logowania | `admin` / `admin` |
| `ACS_PORT` | port lokalnego panelu | `8088` |
| `ACS_BIND` | adres nasłuchu panelu (np. IP serwera w LAN, żeby otwierać panel z innych komputerów) | `127.0.0.1` |
| `ACS_DATA` | katalog danych (zapisane kontrolery, dziennik) | Windows `%APPDATA%\ACB Panel`, macOS `~/Library/Application Support/ACB Panel`, Linux `~/.local/share/acb-panel` |
| `ACS_NO_BROWSER` | `1` = nie otwieraj przeglądarki po starcie | — |
| `ACS_TLS_CERT` / `ACS_TLS_KEY` | pliki PEM certyfikatu i klucza — panel działa po **HTTPS** | — |
| `ACS_ADMIN_LOGIN` / `ACS_ADMIN_PASSWORD` | pierwsze konto administratora panelu (tylko gdy nie ma żadnego konta) | — |
| `ACS_AUTH` | `0` = bez logowania (działa tylko przy `ACS_BIND=127.0.0.1`) | — |
| `ACS_TRUST_PROXY` | `1` = panel za serwerem HTTPS (Caddy, nginx): adres klienta z `X-Forwarded-For`, ciasteczko `Secure` przy `X-Forwarded-Proto: https` | — |
| `ACS_SESSION_HOURS` | wygaśnięcie sesji po tylu godzinach bezczynności (i zawsze po 7 dniach) | `12` |
| `ACS_AUTOCONNECT_DELAY` | po ilu sekundach od startu łączyć kontrolery z „Łącz sam” | `65` |
| `ACS_UDP_PORT` | port kanału UDP kontrolerów (testy na atrapie) | `60000` |
| `ACS_ONLINE_POLL` | co ile sekund sprawdzać stan online zapisanych kontrolerów | `30` |

```bash
ACS_HOST=192.168.1.100 ACS_USER=abc ACS_PWD=654321 python3 acs_panel.py
```

## HTTPS i dostęp zdalny

**Na ten moment HTTPS trzeba skonfigurować we własnym zakresie.** Panel sam z siebie działa po czystym HTTP
i nie wystawia certyfikatu. Dopóki otwierasz go tylko na tym samym komputerze (`http://127.0.0.1:8088`),
ruch nie wychodzi do sieci. Gdy panel ma być dostępny z innych komputerów, udostępnij go po HTTPS — inaczej
hasła do panelu, numery kart i polecenia otwarcia drzwi idą w sieci otwartym tekstem.

Odcinek **panel → kontroler** zawsze zostaje nieszyfrowany (kontrolery ACB nie obsługują HTTPS) — HTTPS chroni
tylko drogę przeglądarka → panel. Kontroler trzymaj w odizolowanej sieci (zob. „Uwagi bezpieczeństwa”).

Są dwie drogi:

1. **Własny certyfikat w panelu** — `ACS_TLS_CERT` i `ACS_TLS_KEY` (pliki PEM). Certyfikat musisz zdobyć
   i odnawiać sam.
2. **Serwer HTTPS przed panelem (zalecane)** — np. [Caddy](https://caddyserver.com/). Tak mamy wystawione panele WWW
   na naszym serwerze: aplikacja słucha tylko na `127.0.0.1`, Caddy przyjmuje połączenia z sieci, sam wystawia i odnawia
   certyfikat i przekazuje ruch do panelu.

### Przykład: Caddy przed panelem

Panel uruchom na `127.0.0.1` z `ACS_TRUST_PROXY=1` (panel bierze wtedy adres klienta z `X-Forwarded-For`,
do dziennika i blokady logowania, i ustawia ciasteczko sesji jako `Secure`):

```bash
ACS_BIND=127.0.0.1 ACS_PORT=8088 ACS_TRUST_PROXY=1 ACS_NO_BROWSER=1 python3 acs_panel.py
```

`/etc/caddy/Caddyfile` (adres `192.168.1.10` zamień na adres komputera z panelem w Twojej sieci):

```caddyfile
{
	# Panel jest na wysokim porcie — bez przekierowań z portu 80
	auto_https disable_redirects
}

# Spreest - Panel ACB — HTTPS w sieci lokalnej
https://192.168.1.10:8088 {
	bind 192.168.1.10          # Caddy zajmuje port tylko na adresie LAN,
	tls internal               # panel trzyma ten sam port na 127.0.0.1 — bez konfliktu
	reverse_proxy 127.0.0.1:8088
}
```

Po zmianie: `sudo systemctl reload caddy`. Panel otwierasz pod **https://192.168.1.10:8088**.

- `tls internal` to certyfikat z wewnętrznego urzędu Caddy — **trzeba go wgrać na każde urządzenie**, z którego
  otwierasz panel (zob. niżej „Wgranie certyfikatu na urządzenia”).
- Masz domenę wskazującą na serwer — wpisz ją zamiast adresu IP i usuń `tls internal`: Caddy sam pobierze
  certyfikat Let's Encrypt (wymaga dostępu z internetu do portu 80 lub 443 albo wyzwania DNS).
- Nie zmieniaj nagłówka `Host` w `reverse_proxy` (domyślnie Caddy go przekazuje) — panel porównuje go
  z nagłówkiem `Origin` i odrzuca zapytania, w których się różnią.
- Adres panelu na innym porcie niż 8088 (np. `https://192.168.1.10:8443`) też zadziała — wtedy `bind` nie jest
  potrzebny.

### Wgranie certyfikatu na urządzenia

Przy `tls internal` (i przy własnym certyfikacie z `ACS_TLS_CERT`, jeśli nie pochodzi z publicznego urzędu)
przeglądarka nie zna wystawcy certyfikatu. **Na każdym urządzeniu, z którego korzystasz z panelu** — komputer
w recepcji, komputer kadr, laptop kierownika, telefon — trzeba raz zainstalować certyfikat główny jako zaufany.
Bez tego przeglądarka pokazuje „Połączenie nie jest prywatne”: da się to kliknąć „Przejdź dalej”, ale wtedy nie
widać różnicy między panelem a podszywającą się pod niego stroną, a część funkcji (np. powiadomienia przeglądarki)
nie działa.

Który plik: **certyfikat główny** Caddy `root.crt` (ważny 10 lat) — nie certyfikat pośredni ani certyfikat strony,
które Caddy odnawia sam co kilka dni. Na serwerze:

```bash
sudo cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt ~/panel-acb-root.crt
```

(ścieżka zależy od instalacji Caddy; `sudo caddy trust` instaluje certyfikat tylko na samym serwerze). Plik
przenieś na urządzenia (pendrive, mail, udział sieciowy) i zainstaluj:

| System | Instalacja |
|---|---|
| Windows | dwuklik `.crt` → *Zainstaluj certyfikat* → *Komputer lokalny* → *Umieść wszystkie certyfikaty w następującym magazynie* → **Zaufane główne urzędy certyfikacji**; albo w wierszu poleceń jako administrator: `certutil -addstore -f Root panel-acb-root.crt`. Chrome i Edge korzystają z tego magazynu. |
| macOS | dwuklik → pęk kluczy **System** → na certyfikacie *Pokaż informacje* → *Zaufanie* → **Zawsze ufaj**; albo `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain panel-acb-root.crt` |
| Linux (Ubuntu/Debian) | `sudo cp panel-acb-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`; Chrome/Chromium na Linuksie ma własną bazę — *Ustawienia → Prywatność i bezpieczeństwo → Zabezpieczenia → Zarządzaj certyfikatami → Urzędy → Importuj* |
| Firefox (każdy system) | jeśli po instalacji w systemie nadal ostrzega: *Ustawienia → Prywatność i bezpieczeństwo → Certyfikaty → Wyświetl certyfikaty → Organy certyfikacji → Importuj*, zaznacz „zaufaj przy identyfikacji witryn” |
| Android | *Ustawienia → Bezpieczeństwo → Więcej ustawień / Szyfrowanie i dane logowania → Zainstaluj certyfikat → Certyfikat CA* (nazwy menu różnią się między producentami) |
| iPhone / iPad | otwórz plik (np. z maila) → *Ustawienia → Pobrany profil → Instaluj*, potem **koniecznie** *Ustawienia → Ogólne → To urządzenie → Ustawienia zaufania certyfikatów* → włącz przy certyfikacie Caddy |

Po instalacji zamknij i otwórz przeglądarkę ponownie. Nowe urządzenie w firmie = ta sama instalacja; po ponownej
instalacji Caddy albo skasowaniu jego katalogu danych powstaje nowy certyfikat główny i trzeba go rozesłać od nowa.

Certyfikatu nie trzeba wgrywać, gdy panel ma certyfikat z publicznego urzędu: Let's Encrypt na własnej domenie
albo certyfikat Tailscale (niżej) — takie przeglądarki znają od razu.

### Dostęp zdalny przez tunel VPN (np. Tailscale)

**Nie wystawiaj panelu ani kontrolera do internetu przekierowaniem portu na routerze.** Do pracy spoza firmy
użyj tunelu VPN — panel jest wtedy osiągalny tylko dla Twoich urządzeń w tunelu. Najprościej przez
[Tailscale](https://tailscale.com/) (WireGuard, darmowy plan dla małych zespołów; podobnie działają ZeroTier,
NetBird, WireGuard albo VPN na routerze):

1. Zainstaluj Tailscale na komputerze z panelem i na urządzeniach, z których chcesz się łączyć (komputer,
   telefon), i zaloguj je na to samo konto (sieć „tailnet”).
2. Komputer z panelem dostaje adres `100.x.y.z` i nazwę MagicDNS, np. `panel.twoja-siec.ts.net`.
3. Udostępnij panel na adresie Tailscale — do wyboru:
   - **Caddy z certyfikatem Tailscale (publiczny, bez ostrzeżeń w przeglądarce)** — w konsoli administracyjnej
     Tailscale włącz *MagicDNS* i *HTTPS Certificates*, pozwól Caddy pobierać certyfikaty
     (`sudo tailscale set --operator=caddy`) i dopisz drugi blok:

     ```caddyfile
     # Spreest - Panel ACB — zdalnie przez Tailscale
     https://panel.twoja-siec.ts.net:8088 {
     	bind 100.x.y.z                       # adres Tailscale komputera z panelem
     	tls {
     		get_certificate tailscale
     	}
     	reverse_proxy 127.0.0.1:8088
     }
     ```

     Panel otwierasz wtedy pod **https://panel.twoja-siec.ts.net:8088** — z sieci firmowej nadal przez blok LAN.
     Po pierwszym włączeniu certyfikatów wykonaj pełny `sudo systemctl restart caddy` (sam `reload` nie zawsze
     ponawia pobranie certyfikatu).
   - **Tailscale Serve (bez Caddy)** — `sudo tailscale serve --bg --https=8088 http://127.0.0.1:8088`; Tailscale sam
     wystawia certyfikat i przekazuje ruch do panelu (panel też z `ACS_TRUST_PROXY=1`). Tego wariantu nie
     sprawdzaliśmy — jeśli zapisy w panelu kończą się odmową, Serve zmienia nagłówek `Host`; wtedy użyj Caddy.
4. W ustawieniach dostępu (ACL) tailnetu ogranicz, kto widzi komputer z panelem — domyślnie każde urządzenie
   w tailnecie widzi wszystkie pozostałe.

Uwagi:

- Tunel łączy przeglądarkę z **panelem**, nie z kontrolerem. Panel musi działać w sieci lokalnej przy kontrolerze
  (tryb online, komputer włączony cały czas) — wyszukiwanie kontrolerów (rozgłoszenie UDP) przez tunel nie działa.
- Nie udostępniaj przez tunel samej podsieci kontrolerów (*subnet router*), jeśli nie musisz — lepiej, żeby
  z kontrolerem rozmawiał tylko panel.
- Panel wymaga logowania także przez tunel. Pierwsze konto administratora przez Caddy/Tailscale wymaga kodu
  z konsoli panelu (przy `ACS_TRUST_PROXY=1` nikt nie jest traktowany jak „ten sam komputer”) — albo ustaw
  `ACS_ADMIN_LOGIN` / `ACS_ADMIN_PASSWORD`.
- Powiadomienia przeglądarki w panelu działają tylko po HTTPS — przez tunel z certyfikatem działają.

## Funkcje

### Nowe w 2.10.0

- **Widok na telefonie.** Panel jest teraz wygodny na małym ekranie:
  - **tabele jako kafelki** — poniżej 640 px każdy wiersz (użytkownicy, log przejść, spis kart, godziny działów,
    czas pracy, dziennik działań…) zamienia się w kafelek „nazwa kolumny → wartość”, bez przewijania w bok;
    nazwy kolumn dopisuje skrypt z nagłówka tabeli (atrybut `data-l`), a układ włącza klasa `stack` na `<body>`,
    więc przy wyłączonym skrypcie zostaje dotychczasowa tabela z przewijaniem,
  - **pola formularzy 16 px** — iPhone nie przybliża strony przy dotknięciu pola (po takim przybliżeniu skala już nie wraca),
  - **większe cele dotknięcia** (przyciski min. 42 px, przyciski ikonowe i pola wyboru powiększone),
  - **górny pasek** mieści się w dwóch liniach: nazwa panelu i konto w pierwszej, połączenie z kontrolerem w drugiej,
  - **pasek zakładek** przewija się płynnie, chowa suwak i sam przewija się do klikniętej zakładki (podkreślenie zamiast paska z boku),
  - **okna** (blokada karty, zmiana karty, korekta, konto) otwierają się jak arkusz przy dolnej krawędzi, z własnym przewijaniem,
  - filtry i paski narzędzi układają się w jedną kolumnę na całą szerokość, a pola o sztywnej szerokości (przelicznik numeru karty,
    potwierdzenie resetu) rozciągają się do szerokości ekranu.

### Nowe w 2.9.0

- **Zmiana numeru karty** („🔁 Zmień kartę” w tabeli użytkowników): nowa karta pod tą samą nazwą, kopia
  uprawnienia starej (UDP `0x50`: drzwi, daty ważności, PIN) i usunięcie starej — stara karta od razu traci dostęp.
  W oknie instrukcja liczenia numeru z nadruku (`FC × 100000 + CN`), kalkulator i „📥 Weź z ostatniej odmowy”.
  Wymiana zostaje w `card_replacements`: czas pracy, „kto w środku” i filtr logu liczą obie karty jako jedną osobę.
- **Pytanie „Czy to wymiana karty?”** przy dodawaniu karty z nazwą osoby, która ma już inną kartę w spisie panelu;
  w „Spisie kart panelu” — „🔁 Zastąpiona kartą…” dla kart wymienionych wcześniej.
  Szczegóły niżej w opisie funkcji („Zmiana numeru karty”).

### Nowe w 2.8.0

- **Czas pracy z par drzwi** (kontroler z jednym czytnikiem na drzwi, np. ACB-004): w zakładce „Drzwi” każde
  drzwi dostają rolę *nie licz* / *odbicie = wejście* / *odbicie = wyjście* (`door_tracking.role`, `user_version` 6).
  Raport czasu pracy, „kto w środku”, lista ewakuacyjna, podgląd na żywo i log przejść biorą kierunek z roli drzwi.
- Wyniki testów na sprzęcie ACB-004 (zdalne otwarcie #2–#4, kod 15 przed datą „ważna od”, przywracanie dat
  po zapisie stroną WWW) — rozdział [Do sprawdzenia na sprzęcie](#do-sprawdzenia-na-sprzęcie).

### Nowe w 2.7.1

- **Zdalne otwarcie nie jest liczone jako osoba w środku.** Wpis „Remote Open” ma w polu karty adres IP
  otwierającego (192.168.1.50 → `3232235826`), nie numer karty. Kopia logu zapisuje go z pustą kartą,
  a migracja bazy (`user_version` 5) czyści wcześniejsze wpisy.

### Nowe w 2.7.0

- **Powód odmowy w logu przejść** — kod z rekordu UDP `0xB0` (strona WWW kontrolera podaje tylko „Denied”),
  kolumna `swipes.reason` (`user_version` 4), uzupełniana po każdym pobraniu logu. Przy karcie, której nie ma
  w kontrolerze: „karta nie jest zapisana w tym kontrolerze” (nazwa pochodzi ze wspólnego spisu kart panelu).
- **„Spis kart panelu”** (Pracownicy i karty): zapamiętane karty z informacją, w których połączonych
  kontrolerach są zapisane, i usuwanie ze spisu kart spoza kontrolerów.

### Nowe w 2.6.2

- **Zmiana IP w „Parametrach sieciowych”** sprawdza adres tak jak „Ustaw adres IP” (sieć komputera z panelem,
  brama, wolny adres); panel sam łączy się pod nowym adresem i poprawia listę zapisanych kontrolerów.

### Nowe w 2.6.1

- Kontroler z loginem i hasłem innym niż podane i fabryczne skan pokazuje jako „nieznany - podaj login i hasło
  kontrolera” — to złe dane logowania, nie nieobsługiwany model.
- Bez udanego logowania numer urządzenia pochodzi z odpowiedzi UDP, więc „Ustaw adres IP” działa także wtedy.

### Nowe w 2.6.0

- **Czyszczenie logów** przez administratora („Ustawienia panelu” → „Czyszczenie logów”): log przejść, zdarzenia
  na żywo, dziennik działań, historia powiadomień; całość albo wpisy sprzed wybranego dnia. Czyści tylko bazę
  panelu (firmware kontrolera nie ma czyszczenia logu), granica w `sync_state.cleared_to`, kopia bazy przed
  usunięciem. Szczegóły niżej w opisie funkcji.

### Nowe w 2.5.0

- **Wyszukiwanie kontrolerów spoza podsieci**: rozgłoszeniowe UDP `0x94` znajduje też kontroler z adresem
  z innej sieci (np. po resecie). Taki kontroler odpowiada, ale HTTP i UDP unicast do niego nie działają,
  więc panel dopasowuje go po numerze urządzenia (szczegóły w [docs/PROTOCOL.md](docs/PROTOCOL.md)).
- **„Ustaw adres IP”** przy kontrolerze w wynikach skanu: rozgłoszeniowe `0x96` (IP, maska, brama), potem
  sprawdzenie nowego adresu ponownym `0x94`. **Jeszcze nie sprawdzone na sprzęcie.**

### Nowe w 2.4.0

- **Masowe dodawanie kart z nazwą właściciela** (zakładka „Pracownicy i karty” → „Dodaj wiele kart naraz”).
  Lista wklejona z arkusza albo spisana ręcznie: jedna osoba w wierszu, numer karty i nazwa właściciela
  oddzielone tabulatorem, średnikiem, przecinkiem albo spacją — w dowolnej kolejności (panel rozpoznaje,
  która część jest numerem). „Sprawdź listę” pokazuje każdy wiersz ze stanem: **nowa**, **już jest**
  w kontrolerze (taka karta dostaje z listy sam dział — nazwy w kontrolerze panel nie zmienia), **powtórka**
  w liście albo **błąd**, razem
  z ostrzeżeniem o numerze powyżej 65535. Karty dodają się po jednej (kontroler nie umie inaczej), więc
  przebieg idzie w tle z podglądem postępu — jak przywracanie z kopii — i przeżywa zmianę zakładki.
  Naraz do 500 wierszy. Opcjonalnie cała lista dostaje od razu **dział** i wspólną datę **ważności**.
- **Przypisanie wielu osób do działu naraz** (tamże, tabela „Użytkownicy”). Pracownicy dodani listą
  są bez działu, więc każdy wiersz ma znacznik wyboru (a nagłówek tabeli — „zaznacz wszystkich z widoku”);
  po zaznaczeniu pasek nad tabelą przypisuje całą paczkę do jednego działu jednym kliknięciem.
  W połączeniu z filtrem „Bez działu” to najkrótsza droga od świeżo wgranej listy do gotowych działów.
  Zaznaczenie trzyma numery kart, więc przeżywa zmianę filtra. PIN-y godzin wejścia przeliczają się raz
  na całą paczkę, nie po jednej osobie.

### Nowe w 2.3.0

- **Numer nadrukowany na karcie a numer w kontrolerze** (karty 13,56 MHz). Czytnik Wiegand-26 przesyła tylko
  24 bity numeru — kod obiektu (8 bitów) i numer karty (16 bitów) — a kontroler skleja je **dziesiętnie**:
  `numer w kontrolerze = kod obiektu × 100000 + numer karty`. Do 65535 numery są takie same, wyżej przeskakują
  (99999 → 134463, 999999 → 1516959). Panel: podpowiedź pod polem „Numer karty” (także ostrzeżenie, gdy wpisany
  numer jest dla kontrolera nieosiągalny albo daje kartę „0”), przelicznik w obie strony w zakładce
  „Pracownicy i karty” oraz przeliczenie pod kursorem przy numerach w tabeli kart i w logu przejść.
  Wzór sprawdzony na sprzęcie — szczegóły w [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Nowe w 2.2.0

- **Tryb online i tryb offline** (`ACS_MODE`, domyślnie `online`) — ten sam program w dwóch wariantach,
  opisane niżej w osobnym rozdziale. Osobne paczki: `ACB-Panel-Offline-<wersja>-*.zip`.

### Nowe w 2.1.0

- **Ostrzeżenie o drzwiach otwartych zbyt długo** (zakładka „Drzwi” → „Ostrzeżenie o otwartych drzwiach”).
  Kontroler sam takiego zdarzenia **nie zgłasza** (sprzęt 2026-09-17: drzwi otwarte ponad 3,5 min nie dały kodu 37,
  tylko `23`/`24` w typie 2), więc czas liczy panel: dla zaznaczonych drzwi pilnuje odstępu między „drzwi otwarte”
  a „drzwi zamknięte”, każde drzwi z własnym progiem 1–1440 min (domyślnie 5). Po przekroczeniu: pasek ostrzegawczy
  na pulpicie (dopóki drzwi są otwarte), wpis ⏰ w podglądzie na żywo (z powiadomieniem przeglądarki) i wiadomość
  e-mail / Telegram / webhook (reguła „Drzwi otwarte dłużej niż ustawiony czas”); po zamknięciu — informacja, jak długo
  były otwarte. Ostrzeżenie idzie **raz na otwarcie**, a alarm z drugiego połączonego kontrolera pokazuje się jak inne
  alerty. Stan drzwi wyznacza **kolejność rekordów**, nie stemple czasu — drgania styku dają kilka zdarzeń `23`/`24`
  w tej samej sekundzie (sprzęt 2026-09-17, rekordy 215–219). Po połączeniu (i po zmianie ustawień) panel odczytuje stan
  z ostatnich 60 rekordów kontrolera (`0xB0`), a dla drzwi, których tam nie ma — z własnego zapisu (`live_events` + `swipes`),
  więc drzwi otwarte **przed uruchomieniem panelu** też są widoczne. Tabela „Ostatnie długie otwarcia” pokazuje zakończone
  otwarcia z 30 dni. Działa tylko przy podłączonym czujniku drzwi i włączonym „Rejestrowaniu zdarzeń”; wejścia czujnika,
  do którego nic nie jest podłączone, kontroler czyta jako „otwarte” — takich drzwi nie zaznaczaj (panel ostrzega o tym
  przy ustawieniu). Ustawienia w tabeli `door_open_watch` (per kontroler i drzwi), stan drzwi tylko w pamięci panelu.

### Nowe w 2.0.0

- **Konta panelu, role i dziennik działań.** Logowanie (hasła PBKDF2-SHA256, sesja w ciasteczku HttpOnly
  SameSite=Strict, zapytania zmieniające stan wymagają nagłówka `X-ACB` i zgodnego `Origin` — ochrona przed CSRF).
  Role: **Podgląd** (pulpit, log, karty, czas pracy, wydruki), **Operator** (+ otwieranie drzwi, karty, ważność
  i blokady, działy, korekty czasu pracy, pobranie kopii użytkowników), **Administrator** (wszystko). Po 5 nieudanych
  logowaniach login i adres IP są blokowane (1 min, potem dłużej, do 15 min). Nie można odebrać uprawnień ostatniemu
  administratorowi. Zakładka „Dziennik działań” (tabela `audit`, 2 lata): kto, skąd (IP), na którym kontrolerze
  i co zrobił — bez haseł i numerów Super Card; także logowania (nieudane też) i działania automatyczne (`system`).
- **HTTPS panelu**: `ACS_TLS_CERT` / `ACS_TLS_KEY` (uzgadnianie TLS w wątku zapytania) albo serwer pośredniczący
  z `ACS_TRUST_PROXY=1`. Kontroler sam HTTPS nie obsługuje — odcinek panel → kontroler zawsze jest nieszyfrowany.
- **Kilka kontrolerów naraz** (`CONNS`, klucz `dev:<nr urządzenia>`). Każdy połączony kontroler ma własne wątki:
  przełączanie godzin wejścia (`_watch_loop(c)`), zdarzenia na żywo (`_live_loop(c)`), a zegar i kopie obejmują
  wszystkie połączone. Interfejs pokazuje kontroler wybrany w sesji (`/api/select`, przełącznik w górnym pasku) —
  każdy zalogowany może oglądać inny. Zmiana działu pracownika przelicza PIN-y na **wszystkich** połączonych.
  „Rozłącz” rozłącza kontroler dla wszystkich.
- **Automatyczne łączenie** („Łącz sam” przy zapisanym kontrolerze z hasłem): po `ACS_AUTOCONNECT_DELAY` s od startu,
  tylko zapamiętanym hasłem (bez prób danych fabrycznych), tylko gdy UDP nie pokazuje offline; nieudane próby
  co 90 s × 3ⁿ (do 1 h), bo każde połączenie zużywa miejsce na połączenie TCP kontrolera. Kontroler rozłączony
  ręcznie nie łączy się sam do ręcznego połączenia albo restartu panelu.
- **Pełna lista użytkowników** (ponad 20): kolejne strony formularzem `ACT_ID_325` (pola ukryte i przycisk `PN`
  ze strony), brakujące karty (lista numerów z UDP `0x58`/`0x5C`) wyszukiwarką. Edycja i usuwanie użytkownika spoza
  pierwszej strony idą przez wyszukiwarkę po numerze karty. Sprawdzone na sprzęcie 2026-09-18 (ACB-002, 25 kart):
  komplet zebrany samym stronicowaniem, edycja i usuwanie spoza pierwszej strony działają. Strony liczą się po
  **slotach, nie po osobach** (slot po skasowanym użytkowniku zostaje pusty, więc pierwsza strona miała 19 wierszy),
  a „Next” za ostatnią stroną zwraca wciąż tę samą stronę — panel przerywa, gdy nie przybywa nikt nowy.
- **Ważność kart** (daty od/do w uprawnieniu WG, zapis `0x50` z weryfikacją `0x5A`): kolumna „Ważność”
  (bez terminu = fabryczne 2029-12-31, „wygasa” ≤ 7 dni, „wygasła”, „od dnia”), daty w oknie edycji, „Ważna do”
  przy dodawaniu karty. Po zapisie strony WWW (nazwa / dostęp) panel przywraca daty, gdyby strona je nadpisała.
  Sprzęt 2026-09-18: strona WWW **zawsze** nadpisuje daty fabrycznymi (2011-01-01 – 2029-12-31) i ustawia bajty
  drzwi #3–#4 na 1 także na kontrolerze dwudrzwiowym; przywracanie dat przez panel działa. Karta po dacie
  „ważna do” dostaje kod odmowy **15** (nie 13 z dokumentacji WG) — ten sam co strefa czasowa, na wejściu
  i na wyjściu (test 2026-09-17).
- **Blokada karty**: dostęp do wszystkich drzwi = 0 (`0x50`), poprzednie bajty drzwi w `card_blocks`, odblokowanie
  je przywraca; opcjonalnie na wszystkich połączonych kontrolerach. Karta zostaje w kontrolerze (log i czas pracy
  zachowują nazwisko). Zablokowanej karty nie da się „odblokować” zaznaczeniem drzwi w edycji.
  Sprzęt 2026-09-17: zablokowana karta dostaje kod odmowy **6**, na wejściu i na wyjściu.
- **Wyjątki w kalendarzu godzin wejścia** (`holidays` w konfiguracji): „brak wejścia” albo „skrócone godziny”
  w zakresie dat, dla wszystkich działów „w godzinach” (działy „o każdej porze” bez zmian); przycisk „+ Święta
  ustawowe” (`pl_holidays`, Wigilia od 2025). Wyjątek zastępuje okno dnia, w którym się zaczyna (`group_allows`).
  Przy **jednej zmianie** lista zadań dostaje zadania na konkretne daty dla dni z wyjątkami i dni po nich, a zadania
  tygodniowe mają zakresy dat z pominięciem tych dni — nigdy dwa zadania z różnym trybem w tej samej minucie
  (kolejność zadań w kontrolerze nie ma znaczenia). Sprawdzone symulacją minuta po minucie (16 dni, 16 wariantów
  godzin i wyjątków, także przez północ). Każdy wyjątek to kilka dodatkowych zadań, a wszystko razy liczba drzwi
  z ograniczeniem. **Lista zadań kontrolera mieści 204 zadania** (sprzęt 2026-09-17: 205. odrzucone), więc panel
  liczy zadania **przed** wyczyszczeniem listy (`entry_tasks_fit`) i odmawia zapisu z podaniem, ile zadań wyszło —
  lista w kontrolerze zostaje wtedy nietknięta. Orientacyjnie: święta ustawowe na rok naprzód to ok. 112 zadań
  na jedne drzwi, czyli przy dwojgu drzwiach limit wypada koło 11–12 osobnych dni. Sąsiednie dni wpisane jako
  jeden okres kosztują dużo mniej niż osobne wyjątki. Przy **kilku zmianach** wyjątki uwzględnia panel.
- **Na żywo i obecni** (Pulpit): zdarzenia z `0x20`/`0xB0` co 1 s zapisywane w `live_events` (120 dni), odmowy
  i alarmy innych połączonych kontrolerów jako komunikat, opcjonalnie powiadomienia systemowe przeglądarki (wymagają
  HTTPS albo 127.0.0.1). „Teraz w środku”: ostatnie przyjęte odbicie z 16 h (kopia logu + zdarzenia na żywo + korekty)
  na drzwiach liczących czas pracy (albo wszystkich); `/print/presence` — lista ewakuacyjna do druku.
  Opisy kodów powodu (`WG_REASONS`) pochodzą z symulatora uhppoted; na sprzęcie sprawdzone 1, 6, 7, 15, 20, 23,
  24, 25, 44. Rekord bez czasu (same zera — zdarza się po zaniku zasilania) panel pomija w podglądzie i w bazie.
- **Powiadomienia** (e-mail SMTP, Telegram, webhook POST JSON z polem `text` — Slack/Teams/Google Chat): powtarzające
  się odmowy karty, nieznana karta (kod 18), zablokowana karta, wejście poza godzinami pracy, alarmy drzwi (typ 3
  albo kody 37–43), kontroler offline dłużej niż N min i powrót. **Uwaga: ACB-002 (V6.62) nie zapisuje zdarzeń
  typu 3** — test 2026-09-17 (czujnik drzwi rozwarty bez karty, drzwi otwarte ponad 3,5 min) dał tylko kody 23/24
  w typie 2, a włączenie zasilania nie dało kodu 28. Reguły alarmowe nie zadziałają na tym sprzęcie. Jedno powiadomienie na regułę i kartę / drzwi co
  N min (`cooldown`), historia w `notify_log`. Hasło SMTP i token bota nie wracają do przeglądarki.
- **Czas pracy**: korekty ręczne ✍️ (`work_corrections`, z powodem i autorem, usunięcie zostawia ślad), norma dzienna
  (domyślna i per dział), dni robocze (pn–pt bez świąt ustawowych i wyjątków „brak wejścia”), saldo, nadgodziny,
  spóźnienia względem początku zmiany działu z tolerancją, dni robocze bez odbić. `/print/worktime?month=` — miesięczna
  karta ewidencji dla każdego pracownika z filtra (druk / PDF z przeglądarki), CSV z korektami i podsumowaniem.
- **Ustawienia panelu**: automatyczna synchronizacja zegarów (odczyt UDP co N h, synchronizacja stroną WWW przy
  różnicy > N s), codzienna kopia zapasowa (baza SQLite przez `backup()` + JSON użytkowników każdego połączonego
  kontrolera) w `<dane>/kopie`, trzymanych N ostatnich; lista plików do pobrania.

- **Wyszukiwanie kontrolerów** w sieci lokalnej (skan podsieci, autodetekcja zakresu).
- **Rozpoznawanie modelu** po liczbie drzwi/przekaźników.
- **Obsługa**: status urządzenia, użytkownicy/karty (dodawanie ręczne i przez
  przyłożenie karty, edycja, usuwanie, wyszukiwanie), log przejść z paginacją,
  zdalne otwieranie drzwi, ustawienia drzwi (nazwa, czas otwarcia, hasła
  z klawiatury, Super Card, rejestr zdarzeń), system (czas, język, konto
  administratora, parametry sieciowe, restart).
- **Nawigacja** (od 1.4.0; menu boczne od 1.10.0): bez połączenia widać tylko zakładkę „Kontrolery”; zakładki
  kontrolera pojawiają się po połączeniu pod nazwą wybranego kontrolera: Pulpit; *Ludzie i ruch* — Pracownicy
  i karty, Log przejść, Czas pracy; *Konfiguracja* — Drzwi, Godziny wejścia, Hasła i Super Card, System.
  Otwarta zakładka jest w adresie strony (`#hours` itd.), więc odświeżenie strony zostaje w tym samym miejscu.
  Od 2.0.0 sekcja *Panel* (administrator): Powiadomienia, Dziennik działań, Konta panelu, Ustawienia panelu;
  zakładki i przyciski, do których rola konta nie ma uprawnień, są ukryte (serwer i tak sprawdza rolę).
  Na wąskim ekranie (≤ 900 px) menu jest poziomym paskiem nad treścią.
- **Przejrzysty układ** (od 1.10.0): każda zakładka ma nagłówek z krótkim opisem; filtry logu i czasu pracy
  są w jednej karcie z tabelą; długie objaśnienia są zwinięte („▸ Jak to działa…”); ostrzeżenie o HTTP
  zajmuje jedną zwijaną linię; stan urządzenia na Pulpicie pogrupowany (Urządzenie / Stan / Sieć), a drzwi
  to kafelki z nazwą, czasem otwarcia i przyciskiem „Otwórz”. W „Drzwiach” jeden przycisk „Zapisz” na wiersz
  (zapisuje tylko zmienione pola: nazwę i/lub czas otwarcia). Dawna zakładka „Ustawienia drzwi” jest
  podzielona na „Drzwi”, „Godziny wejścia” i „Hasła i Super Card”.
- **Stan online zapisanych kontrolerów** (od 1.5.0): panel co `ACS_ONLINE_POLL` s (domyślnie 30) wysyła do
  każdego zapisanego kontrolera odczyt zegara `0x32` przez UDP 60000 z numerem urządzenia z wpisu — bez
  logowania i bez połączenia TCP. Kolumna „Stan”: 🟢 online (od kiedy), 🔴 offline (ostatnio online / od kiedy nie
  odpowiada), ❔ nieznany (wpis bez numeru urządzenia). Historia tylko od uruchomienia panelu.
- **Działy** (od 1.1.0): grupowanie użytkowników i kart na działy w zakładce „Pracownicy i karty”
  (lista pogrupowana po działach, filtr, przypisanie z listy przy użytkowniku).
- **Log przejść z historią** (od 1.1.0): panel kopiuje log kontrolera do swojej bazy (przyrostowo,
  do pierwszej strony ze znanymi wpisami; pierwsze pobranie całości w tle) i pokazuje go z filtrami
  pracownik / dział / zakres dat. Emotki kierunku: ➡️🚪 wejście, 🚪➡️ wyjście, ⛔ odmowa, 🔓 otwarcie
  z panelu, ⚙️ zdarzenie urządzenia.
- **Czyszczenie logów** (od 2.6.0, tylko administrator): „Ustawienia panelu” → „Czyszczenie logów”. Do wyboru
  log przejść, zdarzenia na żywo, dziennik działań i historia powiadomień; całość albo wpisy sprzed wybranego dnia;
  log przejść i zdarzenia także dla jednego kontrolera. Czyści się tylko baza panelu — firmware kontrolera nie
  ma czyszczenia logu (docs/PROTOCOL.md). Żeby następne pobranie nie przywróciło usuniętych wpisów, panel
  zapisuje w `sync_state.cleared_to`, do kiedy log wyczyszczono, i starszych wpisów z kontrolera już nie
  przyjmuje. Przed usunięciem powstaje kopia całej bazy (`kopie/przed-czyszczeniem-logow_*.db`, 5 ostatnich),
  a samo czyszczenie trafia do dziennika działań (wpis powstaje po usunięciu, więc zostaje także po
  wyczyszczeniu dziennika).
- **Czas pracy** (od 1.1.0; własna zakładka od 1.4.0): w zakładce „Drzwi” zaznacza się drzwi, które liczą
  pobyt; raport w zakładce „Czas pracy” (własne filtry, przelicza się sam po zmianie filtra) łączy odbicia na czytniku wejścia i wyjścia w pobyty (per pracownik, dzień,
  z rozwinięciem godzin, eksport CSV).
  **Pary drzwi (od 2.8.0, ACB-004)** — przy drzwiach jest tylko czytnik wejścia, więc w zakładce „Drzwi” każde
  drzwi dostają rolę: *nie licz* / *odbicie = wejście* / *odbicie = wyjście* (`door_tracking.role`, migracja
  `user_version` 6). Raport, „kto w środku”, lista ewakuacyjna, podgląd na żywo i log przejść biorą kierunek
  z roli drzwi (`door_roles`, `reader_sql`); raport liczy wtedy wszystkie drzwi razem. Wymaga co najmniej jednych
  drzwi wejścia i jednych wyjścia. Godzin wejścia nie ustawia się na drzwiach wyjścia (zablokowałyby wyjście).

- **Zmiana numeru karty** (od 2.9.0): przycisk „🔁 Zmień kartę” w tabeli użytkowników (Pracownicy i karty).
  Strona WWW kontrolera nie zmienia numeru karty, więc panel dodaje nową kartę pod tą samą nazwą (`ACT_ID_312`),
  kopiuje uprawnienie starej przez UDP `0x50` (drzwi, daty ważności, PIN) i usuwa starą (`ACT_ID_324`) — stara
  karta od razu przestaje otwierać drzwi. Kolejność kroków: przy błędzie w połowie stara karta dalej działa, a panel
  mówi, co zostało do zrobienia. Zablokowanej karty nie zmienia (najpierw odblokowanie). Wymaga kanału UDP.
  Nowy numer sprawdzany przed zapisem: numer nieosiągalny dla czytnika (5 ostatnich cyfr > 65535) i wielokrotność
  16777216 są odrzucane z podpowiedzią. W oknie: instrukcja liczenia numeru z nadruku (`FC × 100000 + CN`),
  kalkulator i przycisk „📥 Weź z ostatniej odmowy” — nową kartę przykłada się do czytnika, kontroler ją odrzuca,
  a panel bierze numer z tej odmowy (`/api/cards/last-denied`, ostatnie 10 min, karta spoza kontrolera).
  W panelu wymiana zostaje w `card_replacements` (stary → nowy numer): nazwa i dział przechodzą na nowy numer,
  a czas pracy, „kto w środku” i filtr logu po pracowniku liczą obie karty jako jedną osobę (`card_aliases`).
  **Pytanie przy dodawaniu karty**: gdy nazwa (bez różnicy wielkości liter i spacji) należy już do innej karty
  w spisie panelu, panel pyta „Czy to wymiana karty?” — wymiana (stara karta w kontrolerze traci dostęp; karta
  spoza kontrolera zostaje tylko połączona w panelu) albo osobna karta. W „Spisie kart panelu” karta spoza
  kontrolerów ma „🔁 Zastąpiona kartą…” (`/api/cards/link`) — dla kart wymienionych przed 2.9.0.

- **Godziny wejścia działów** (od 1.8.0; wcześniej 1.2.0–1.7.0 godziny per drzwi + wyjątek „o każdej porze”):
  w zakładce „Godziny wejścia” zaznacza się drzwi z ograniczeniem, a każdy dział (i wiersz „Pracownicy bez działu”)
  dostaje tryb: w godzinach od–do z dniami tygodnia / o każdej porze / brak wejścia. „Do” ≤ „od” = okno przez
  północ (dni = dzień rozpoczęcia), „od” = „do” = cała doba. Wyjście działa zawsze.
  Realizacja zależy od planu (`entry_plan`, liczony z grup, które mają karty w kontrolerze; kolumna `plan`):
  **jedna zmiana** (wszystkie takie grupy mają te same godziny i dni albo „o każdej porze”) — lista zadań
  kontrolera (UDP 60000, `ACS_UDP_PORT`) sama przełącza drzwi: o 00:00, „od” i „do” tryb 5 albo 6 wynikający
  z godzin w danym dniu tygodnia (także okna przez północ), PIN 0 mają na stałe tylko grupy „o każdej porze” —
  **po zapisie działa bez panelu**; **kilka zmian** (różne godziny albo grupa z kartami na „brak wejścia”) —
  drzwi stale w trybie 6 (zadanie 00:00 + „na teraz”), a panel (`entry_pins_sync`, UDP `0x50`) daje PIN 0
  kartom grup, które w tej chwili mogą wchodzić, pozostałym kartom z PIN-em 0 przywraca 345678 (kontroler nie
  pyta o PIN kart z PIN-em 0 — ACB-002, 2026-09-17). Wątek `_watch_loop` co 0,2 s liczy zbiór takich grup
  zegarem kontrolera i synchronizuje przy jego zmianie, po połączeniu i co 10 min (po błędzie co 30 s);
  **przy kilku zmianach panel musi być stale połączony** — bez niego PIN-y zostają w ostatnim stanie.
  Synchronizacja (także po zmianie działu pracownika) przelicza plan i gdy różni się od zapisanego, sama
  przepisuje listę zadań (najpierw PIN-y, potem zadania). PIN jest jeden na kartę, więc godziny działu są
  wspólne dla wszystkich drzwi z ograniczeniem danego kontrolera; przełącza tylko aktywny kontroler.
  Zapasowo wątek czyta stan (`0x20`/`0xB0`) i po odmowie wejścia z kodem 7 karty z grupy mogącej wejść otwiera
  drzwi (`0x40`, awaryjnie WWW; tylko przy dostępie „zawsze” w `0x5A`); wejścia w `entry_passes` — log
  „wejście (otworzył panel)”, raport czasu pracy liczy je jak przyjęte.
  Konfiguracja w `entry_hours` (`config` edytowana, `applied` zapisana na kontrolerze — według niej przełącza
  panel): `{"doors": {"1": true}, "groups": {"<id działu>|nodept": {mode, start, end, days}}}`. Nowy dział ma
  „brak wejścia”. Migracja bazy (`PRAGMA user_version` 1) przenosi starą konfigurację: godziny pierwszych drzwi
  z ograniczeniem dostają działy i pracownicy bez działu, działy „o każdej porze” — tryb `always`; osobne wyjątki
  pracowników (1.6.0, `entry_free_people`) nie są przenoszone. Zapis zastępuje całą listę zadań kontrolera.
  Oba plany sprawdzone na symulatorze UDP (lista zadań jednej zmiany dodatkowo symulacją 15 dni minuta po minucie
  dla 8 okien, w tym przez północ); na sprzęcie tylko tryby 5/6 i PIN 0. Zanik zasilania do sprawdzenia.
- **Kopia zapasowa użytkowników** (od 1.9.0): w zakładce „Pracownicy i karty” przycisk „Pobierz kopię” zapisuje
  plik JSON (`kind: acb-panel-users`, `format: 1`) z kartami i nazwami wszystkich użytkowników połączonego
  kontrolera, pogrupowanymi po działach panelu (także pustych), plus `no_department`. Numery kart z kanału UDP
  (`0x58`/`0x5C` — strona Users pokazuje tylko 20 pierwszych), nazwy ze strony Users: pierwsza strona, resztę
  wyszukiwarką po numerze karty; bez UDP kopia powstaje tylko, gdy wszyscy mieszczą się na pierwszej stronie.
  Kopia celowo **nie zawiera** uprawnień do drzwi, PIN-ów ani godzin wejścia — zależą od podłączenia przekaźników.
  „Przywróć z pliku” pokazuje najpierw porównanie z kontrolerem (brakujące karty, nowe działy, zmiany działów,
  karty spoza kopii), potem w tle (`/api/backup/restore`, postęp co 1 s): tworzy brakujące działy, dodaje
  brakujące karty przez stronę WWW (dostęp do wszystkich drzwi, jak każda nowa karta) i ustawia przypisania
  do działów z kopii; nazw istniejących kart nie zmienia, niczego nie usuwa. Na końcu `entry_pins_sync`.
  Sprawdzone na atrapie kontrolera (27 kart, lista WWW po 20), nie na sprzęcie.

### Dane panelu (`acb-panel.db`)

2.1.0 dokłada tabelę `door_open_watch` (drzwi z pilnowanym czasem otwarcia i próg w minutach, per kontroler).

2.0.0 dokłada tabele: `panel_users`, `panel_sessions` (skrót SHA-256 tokenu, oglądany kontroler), `audit`, `settings`
(JSON: `work`, `maintenance`, `notify`), `card_blocks`, `live_events`, `work_corrections`, `notify_log`. Stare tabele bez
zmian — wersja 1.10.0 działa na tej samej bazie (nowych tabel nie widzi).

SQLite w katalogu danych (`ACS_DB` zmienia ścieżkę): `departments`, `people` (pracownik = numer karty bez
zer poprzedzających, wspólny dla wszystkich kontrolerów), `door_tracking` i `swipes` (kopia logu; oba
per kontroler — klucz `dev:<nr urządzenia>`, awaryjnie `ip:<adres>`), `sync_state` (czy cały log został
raz pobrany do końca — dopiero wtedy pobieranie zatrzymuje się na znanych wpisach).

Zasady liczenia czasu pracy (`work_sessions()`): pobyt = pierwsze wejście → najbliższe wyjście na drzwiach
z zaznaczoną analizą (tylko odbicia dozwolone, z kartą); powtórne wejście w trakcie pobytu go nie przerywa;
pobyt zaliczany do dnia wejścia; wejście bez wyjścia (albo dłuższe niż 16 h — `MAX_SESSION`) i wyjście bez
wejścia to uwagi ❓, nieliczone; dzisiejsze wejście bez wyjścia = „w środku”, liczone do chwili raportu.
Opcja miejsca „wszystkie zaznaczone drzwi razem” pozwala wejść jednymi drzwiami i wyjść drugimi (ACB-002).

## Obsługiwane modele

Model rozpoznawany jest po liczbie niezależnych drzwi/przekaźników. Liczbę drzwi panel odczytuje
dopiero po zalogowaniu się do kontrolera. Kontroler z loginem i hasłem innym niż podane i fabryczne
skan pokazuje jako „nieznany - podaj login i hasło kontrolera”. Nie jest to nieobsługiwany model:
wystarczy połączyć się z nim, podając jego dane logowania.

| Model | Drzwi | Status profilu |
|---|---|---|
| **ACB-001** | 1 | ✅ w pełni zweryfikowany na sprzęcie |
| **ACB-002** | 2 (2 przekaźniki, 4 czytniki: wejście + wyjście na drzwi) | ✅ zweryfikowany na sprzęcie (odczyty, użytkownicy, auto-dodawanie, nazwa drzwi #2); zdalne otwieranie i hasła drzwi #2 niesprawdzone fizycznie |
| **ACB-004** | 4 | ✅ zweryfikowany na sprzęcie (nr 400000004): odczyty, nazwy / czasy / hasła drzwi #3–#4, użytkownicy z uprawnieniami do drzwi, auto-dodawanie, zdalne otwieranie drzwi #1–#4 (2026-09-22) |

> **Uwaga — brak szyfrowania HTTPS w kontrolerach:** kontrolery **ACB-001**, **ACB-002** i **ACB-004**
> nie obsługują szyfrowania HTTPS (tylko czysty HTTP), więc ruch panel → kontroler zawsze jest nieszyfrowany.
> Zalecane podłączenie sieciowe:
> - kontroler podłączony **bezpośrednio do serwera** z panelem, albo
> - kontroler i serwer w **osobnym VLAN-ie na switchu zarządzalnym** (tylko kontroler i serwer, bez innych urządzeń),
>
> a sam panel wystawiony dla użytkowników **po HTTPS** (`ACS_TLS_CERT` / `ACS_TLS_KEY` albo serwer HTTPS
> przed panelem z `ACS_TRUST_PROXY=1`) — patrz [Uwagi bezpieczeństwa](#uwagi-bezpieczeństwa).

Cała rodzina używa tego samego protokołu HTTP. Ustawienia drzwi
(nazwa, czas otwarcia, 4 hasła) są osobne dla każdych drzwi, a log przejść pokazuje drzwi
i czytnik (wejście/wyjście). Każdy użytkownik ma osobne uprawnienie do każdych drzwi
(„Edytuj / dostęp” na liście użytkowników; nowa karta ma dostęp do wszystkich drzwi).

**Zapytania naraz:** zarówno ACB-001, jak i ACB-002 obsługują **jedno zapytanie i jedno
połączenie naraz**. Drugie równoległe połączenie albo pipelining zawieszają komunikację
(pomiary: [docs/PROTOCOL.md](docs/PROTOCOL.md#współbieżność--ile-zapytań-naraz-pomiar-na-acb-002-2026-09-14)).
Gdy panel jest połączony, nie otwieraj interfejsu kontrolera w przeglądarce.

## Tryb online i tryb offline

Ten sam `acs_panel.py` pracuje w dwóch trybach; wybiera je zmienna `ACS_MODE` ustawiana w pliku startowym paczki.

| | **online** (domyślny) | **offline** |
|---|---|---|
| Po co | panel na komputerze/serwerze włączonym całą dobę | program uruchamiany doraźnie, np. raz w miesiącu po wyciąg czasu pracy |
| Połączenie z kontrolerem | trwałe, panel łączy się sam („Łącz sam”) i pilnuje połączenia | nawiązywane po starcie i trzymane do zamknięcia programu; panel łączy się z **każdym** zapisanym kontrolerem, który ma zapamiętane hasło (bez czekania na `ACS_AUTOCONNECT_DELAY` — domyślnie 0 s) |
| Po połączeniu | wątki `_watch_loop` (PIN-y godzin wejścia) i `_live_loop` (zdarzenia, drzwi, powiadomienia) | jedno pobranie logu przejść (`_offline_pull`), żeby czas pracy i log były aktualne bez klikania |
| Godziny wejścia | jedna zmiana i kilka zmian | **tylko jedna zmiana** — zapis planu `multi` jest odrzucany (`offline_shift_error`) |
| Zdarzenia na żywo, powiadomienia, ostrzeżenie o otwartych drzwiach | działają | wyłączone |

Wyłączone funkcje są **ukryte w interfejsie** (atrybut `data-online` w HTML, `applyVisibility()` w JS; `data-offline`
oznacza elementy tylko dla trybu offline) i **odrzucane przez API** (`ONLINE_ONLY` → HTTP 409 z wyjaśnieniem), żeby
stara karta przeglądarki albo własny skrypt klienta nie dostały pozornie poprawnej odpowiedzi. Panel offline pokazuje
też baner z listą tego, czego nie robi, a w zakładce „Godziny wejścia” ostrzega, jeśli na kontrolerze siedzi
harmonogram wielozmianowy zapisany wcześniej przez panel online (`offline_stale`) — wtedy nikt nie przełącza PIN-ów
i karty zostają w ostatnim stanie.

Reszta działa tak samo: czas pracy z raportami i kartą miesięczną, log przejść, pracownicy i karty, lista osób
w środku (liczona z pobranego logu), otwieranie drzwi, ustawienia kontrolera, kopie, konta panelu i dziennik działań.
Oba warianty korzystają z tego samego katalogu danych, więc można je wymienić bez utraty logu i ustawień.

## Paczki dla klientów (Windows / macOS / Linux)

```bash
python3 packaging/build_release.py                  # online, wszystkie systemy
python3 packaging/build_release.py windows          # online, wybrany
python3 packaging/build_release.py --offline        # offline, wszystkie systemy
python3 packaging/build_release.py --all-modes      # oba warianty (6 paczek)
```

Wynik w `dist/`: `ACB-Panel-<wersja>-{Windows,macOS,Linux}.zip` (tryb online) i
`ACB-Panel-Offline-<wersja>-{Windows,macOS,Linux}.zip` (tryb offline) — gotowe do wrzucenia
np. na Google Drive (wrzucaj same pliki ZIP, nie rozpakowane foldery — inaczej zginą uprawnienia
plików na macOS/Linuksie). Klient rozpakowuje i uruchamia dwuklikiem, bez instalacji:

| Paczka | Start (online) | Start (offline) | Zawiera Pythona dla |
|---|---|---|---|
| Windows (~10 MB) | `Uruchom panel ACB.bat` | `Uruchom panel ACB (offline).bat` | Windows 10/11 x64 (na ARM przez emulację) |
| macOS (~37 MB) | `Uruchom panel ACB.command` | `Uruchom panel ACB (offline).command` | Apple Silicon i Intel (wybór automatyczny) |
| Linux (~48 MB) | `uruchom-panel-acb.sh` | `uruchom-panel-acb-offline.sh` | x86_64 i ARM64 (glibc 2.17+) |

Oba warianty mają ten sam `acs_panel.py`; różnią się plikiem startowym (`ACS_MODE=offline`), nazwą folderu po
rozpakowaniu (`ACB Panel` / `ACB Panel Offline` — mogą leżeć obok siebie) i treścią `INSTRUKCJA.txt`.
Warianty opisuje `VARIANTS` w `packaging/build_release.py`, a szablony mają znaczniki `{{MODE_*}}`, `{{TOP}}`
i `{{START}}` podstawiane przez `fill()`.

Paczka = `acs_panel.py` + przenośny CPython z [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
(sumy SHA256 sprawdzane przy pobieraniu, zbędne moduły jak tkinter/pip wycięte) + plik startowy + `INSTRUKCJA.txt`.
Nic nie jest kompilowane, więc wszystkie trzy paczki buduje się na dowolnym systemie. Szablony startów i instrukcji:
`packaging/templates/`. Nowa wersja: podbij `APP_VERSION` w `acs_panel.py`; nowszy Python: `PBS_RELEASE` / `PBS_PYTHON`
w skrypcie budującym.

Programy nie są podpisane cyfrowo: przy pierwszym uruchomieniu Windows (SmartScreen) i macOS (Gatekeeper)
pokazują ostrzeżenie — instrukcje w paczkach opisują, jak je obejść. Usunięcie ostrzeżeń wymaga certyfikatu
podpisu kodu (Windows) i konta Apple Developer z notaryzacją (macOS).

## Struktura kodu (`acs_panel.py`)

Aplikacja jest w jednym pliku dla łatwości uruchamiania i przenoszenia.

| Sekcja | Odpowiada za |
|---|---|
| `MODELS`, `model_for_doors()` | rejestr modeli (dodanie modelu = jeden wpis) |
| `class AcbController` | protokół HTTP: logowanie, status, użytkownicy, drzwi, konfiguracja |
| `discover()`, `_probe()`, `_port_open()`, `local_subnet()` | wyszukiwanie w sieci |
| `connect()`, `require_active()`, `ACTIVE` | zarządzanie aktywnym kontrolerem |
| `db()`, `departments()`, `swipe_sync_start()`, `log_local()`, `worktime()` | dane panelu: działy, kopia logu, czas pracy |
| `bulk_add_preview()`, `bulk_add_start()`, `people_assign_bulk()` | masowe dodawanie kart z listy i przypisanie wielu osób do działu |
| `CONNS`, `current_controller()`, `_register()`, `connect()` | połączone kontrolery, kontroler oglądany w sesji |
| `priv_parse()`, `card_validity()`, `card_block()` | uprawnienia kart WG: ważność i blokady |
| `holidays_normalize()`, `group_allows()`, `entry_hours_tasks()` | godziny wejścia z wyjątkami w kalendarzu |
| `_live_loop()`, `presence()`, `notify_event()`, `notify_send()` | zdarzenia na żywo, obecni, powiadomienia |
| `_door_init()`, `_door_event()`, `_door_check()`, `door_watch_config()` | ostrzeżenie o drzwiach otwartych zbyt długo |
| `worktime()`, `correction_add()`, `pl_holidays()`, `print_worktime()` | czas pracy, korekty, wydruki |
| `_maintenance_loop()` | automatyczne łączenie, zegary, kopie, czyszczenie starych wpisów |
| `ROLES`, `login()`, `session_get()`, `panel_user_save()`, `audit()` | konta panelu, sesje, dziennik działań |
| `ROUTES_GET` / `ROUTES_POST` | mapa API: ścieżka → (funkcja, minimalna rola); `AUDIT_POST` — opis do dziennika |
| `PAGE` | interfejs WWW (HTML + CSS + JS, inline) |
| `Handler`, `main()` | serwer HTTP |

Szczegóły rozpracowanego protokołu urządzenia: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Dziennik komunikacji

Każde zapytanie do kontrolera i każde nowe połączenie TCP jest zapisywane w
`acb-device.log` w katalogu danych (bez wartości pól — bez haseł; powyżej 5 MB plik przechodzi
w `.1`). Ścieżkę zmienia `ACS_DEVICE_LOG`.

## Uwagi bezpieczeństwa

- Kontrolery często pracują na domyślnych danych (`admin/admin`, `abc/654321`)
  i po czystym HTTP — hasło jest przesyłane otwartym tekstem.
- **Ruch nie jest w żaden sposób szyfrowany** (kontroler obsługuje tylko HTTP, panel także
  działa po HTTP): login, hasło, numery kart i polecenia otwarcia drzwi da się podsłuchać w sieci.
  Panel pokazuje o tym stałą adnotację po połączeniu z kontrolerem. Używaj urządzenia w sieci
  lokalnej z rozwagą — w wydzielonej sieci/VLAN, bez dostępu z Wi-Fi dla gości.
- Zmień domyślne dane logowania i trzymaj kontroler w odizolowanej sieci/VLAN;
  nigdy nie wystawiaj go bezpośrednio do internetu.
- **Kontroler nie obsługuje HTTPS** (firmware „Web Controller” V6.62: tylko HTTP na porcie 80 i UDP 60000) —
  nie da się tego włączyć. Szyfrować można tylko odcinek przeglądarka → panel (`ACS_TLS_CERT` albo serwer HTTPS
  przed panelem). Dotyczy to wszystkich modeli: ACB-001, ACB-002 i ACB-004. Zalecana topologia: kontroler
  podłączony bezpośrednio do serwera z panelem albo kontroler i serwer w wydzielonym VLAN-ie na switchu
  zarządzalnym, a panel udostępniony użytkownikom wyłącznie po HTTPS (konfiguracja: „HTTPS i dostęp zdalny”).
- Panel słuchający w sieci (`ACS_BIND` inny niż 127.0.0.1) bez HTTPS: hasła do panelu idą otwartym tekstem —
  panel ostrzega o tym przy starcie i w „Ustawieniach panelu”.
- Katalog danych zawiera hasła zapisanych kontrolerów, numery kart, nazwiska i kopie — chroń go.

## Do sprawdzenia na sprzęcie

- Zmiana numeru karty (2.9.0) na ACB-004: kopia uprawnienia (`0x50`) dla karty dodanej chwilę wcześniej stroną WWW,
  usunięcie starej, „Weź z ostatniej odmowy”. Sprawdzone na atrapie czterodrzwiowej (29 testów API + interfejs w jsdom).

### Sprawdzone na sprzęcie 2026-09-22 (ACB-004)

- **Zdalne otwieranie drzwi #2–#4** (`0x40`): przekaźniki zadziałały, rekordy z kodem 44 na właściwych drzwiach.
- **Karta przed datą „ważna od”**: odmowa kodem **15** — tym samym, co po dacie „ważna do” i poza strefą czasową.
- **Strażnik dat po zapisie stroną WWW** (zmiany z 2.0.2) na kontrolerze czterodrzwiowym: strona nadpisała daty,
  panel je przywrócił; bajty drzwi zgodne z formularzem (`[1,0,1,0]`) — na ACB-004 strona nie ustawia #3–#4 na 1.
  Lista zadań godzin wejścia zapisuje się na cztery drzwi (4 zadania „na teraz”).
- **Ostrzeżenie o drzwiach otwartych zbyt długo** (2.1.0, drzwi #1, próg 1 min): ostrzeżenie po minucie i koniec
  po zamknięciu; drgania styku (kilka 23/24 w tej samej sekundzie) liczone jako jedno otwarcie. Panel rozłączony
  przy otwartych drzwiach i połączony po 24 min odczytał stan z rekordów `0xB0` — ostrzeżenie od razu przy
  połączeniu (z właściwą godziną otwarcia), zamknięcie 7 s później je zakończyło.
- **Czas pracy z par drzwi** (2.8.0, #1 = wejście, #2 = wyjście): log, podgląd na żywo, „kto w środku”
  i raport liczą odbicie na #2 jako wyjście. Karta usunięta z kontrolera po wejściu zostaje „w środku”
  (nie może się już odbić przy wyjściu) — do korekty ręcznej albo do wygaśnięcia po 16 h.

### Sprawdzone na sprzęcie 2026-09-17/18 (ACB-002, V6.62)

- **Numer karty z czytnika 13,56 MHz**: potwierdzony wzór `FC × 100000 + CN` (24 bity, `FC` 8-bitowe) —
  pomiary 10000, 12345, 99999, 100000, 999999 i 16777216 (ta ostatnia w ogóle nie trafia do logu).

- **Stronicowanie `ACT_ID_325`**: 25 kart, komplet zebrany samym stronicowaniem; edycja i usuwanie z wyników
  wyszukiwarki działają. Strony liczą sloty, nie osoby; „Next” za końcem listy powtarza ostatnią stronę.
- **Ważność**: karta po dacie „ważna do” — odmowa kodem **15** (wejście i wyjście). Zapis stroną WWW nadpisuje
  daty fabrycznymi i ustawia drzwi #3–#4 na 1; strażnik dat w panelu przywraca je poprawnie.
- **Blokada** (`0x50`, drzwi = 0): odmowa kodem **6** (wejście i wyjście).
- **Alarmy**: brak. Ten firmware nie zapisuje zdarzeń typu 3 — rozwarty czujnik drzwi bez karty i drzwi otwarte
  ponad 3,5 min dały tylko kody 23/24 w typie 2, włączenie zasilania nie dało kodu 28 (tylko pusty rekord
  i „drzwi otwarte” dla każdych drzwi z niepodłączonym czujnikiem). Wejść pożarowego i antywłamaniowego
  nie było czym sprawdzić.
- **Pojemność listy zadań**: **204 zadania** (205. odrzucone, `0xA8` odpowiada 0). Jedno zadanie zapisuje się
  ok. 0,26 s, pełna lista to prawie minuta. Ostatnie przyjęte zadanie działa (sprawdzone odbiciem karty).
- **Godziny wejścia po zaniku zasilania**: lista zadań przetrwała restart, karta wchodziła dalej zgodnie z planem.

## Testy (atrapa kontrolera)

Testy 2.4.0 (masowe dodawanie kart i masowe przypisanie do działu) przechodziły na atrapie: rozdzielniki
i kolejność kolumn w liście, powtórki, karty już obecne w kontrolerze, błędne wiersze, limit 500, dział i data
ważności dla całej listy, dziennik działań, zaznaczanie w tabeli (z filtrem działu) oraz widok roli „Podgląd”.
Sprawdzone też w paczce offline (Linux) połączonej z atrapą.

Testy 2.0.0 przechodziły na atrapie (HTTP + UDP WG: logowanie, Users po 20 ze stronicowaniem, wyszukiwarka, edycja,
usuwanie, Configure, zegar, Swipe; uprawnienia `0x50`/`0x5A`/`0x5C`, zdarzenia, zadania). Testowej kopii panelu
zawsze podawaj osobne `ACS_DATA`, **`ACS_SAVED`** (bez tego przy pierwszym starcie skopiuje się stara lista
`controllers.json` z katalogu programu — z prawdziwymi kontrolerami), `ACS_DEVICE_LOG`, `ACS_PORT` i `ACS_UDP_PORT`.

## Licencja

Spreest - Panel ACB jest wolnym oprogramowaniem na licencji
[GNU General Public License v3.0](LICENSE): można go używać, zmieniać i rozpowszechniać,
a zmienione wersje trzeba udostępniać na tej samej licencji, razem z kodem źródłowym.
Program jest dostarczany bez jakiejkolwiek gwarancji.
