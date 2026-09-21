# Protokół kontrolera „Web Controller" (rodzina ACB)

Dokumentacja protokołu rozpracowana na urządzeniu **ACB-001**
(Driver Version `V6.62.51215`, Device NO `100000001`) i potwierdzona na **ACB-002**
(Driver Version `V6.62.51215`, Device NO `200000002`, 2 drzwi / 2 przekaźniki / 4 czytniki)
oraz **ACB-004** (Driver Version `V6.62.51215`, Device NO `400000004`, 4 drzwi; 2026-09-15).
Na wszystkich trzech urządzeniach pierwsza cyfra numeru urządzenia była równa liczbie drzwi (1/2/4) — obserwacja, model panel i tak rozpoznaje po drzwiach.

Cała komunikacja to zwykłe formularze **HTTP POST** na porcie **80**, kierowane
do endpointów `ACT_ID_<n>`. Odpowiedzi to strony HTML (interfejs kontrolera),
z których parsujemy dane. Port **60000** (UDP) to natywny binarny kanał SDK — kontrolery
to sprzęt **WG (Weigeng)**, patrz „Kanał UDP 60000” na końcu.

## Cechy kluczowe

- **Brak cookies / bezstanowa sesja HTTP.** Stan („na której stronie jesteśmy")
  kontroler trzyma po swojej stronie i jest on **sekwencyjny**: wiele operacji
  wymaga wykonania kroków po kolei w jednej sesji (np. najpierw otwarcie listy,
  potem akcja na wierszu). Ponowne zalogowanie resetuje kontekst do „Home".
- **Jednowątkowość.** Kontroler źle znosi równoległe żądania — potrafią
  powodować timeouty i błędną interpretację. W programie dostęp jest
  serializowany zamkiem (`threading.Lock` per kontroler).
- **Kodowanie UTF-8** (należy ustawić `response.encoding = "utf-8"`).
- **LIMIT 11 POŁĄCZEŃ TCP NA URUCHOMIENIE (krytyczne).** Stos TCP urządzenia
  (ACB-001, firmware V6.62.51215) nie zwalnia zasobu po zamkniętym połączeniu.
  11 połączeń od włączenia działa, **12. połączenie zawiesza kontroler, a watchdog
  go restartuje** (wpis `Reboot` w logu). Zweryfikowano pomiarem: 60 zapytań,
  każde nowym połączeniem → zawieszenie dokładnie co 10–11 połączeń; 60 i 125
  zapytań jednym połączeniem keep-alive → 0 zawieszeń. Bezczynne połączenie
  keep-alive nie jest zamykane przez urządzenie (sprawdzone do 120 s).
  Wniosek: **wszystkie zapytania wysyłaj jednym trwałym połączeniem HTTP/1.1**
  (odpowiedzi mają `Content-Length`); nie otwieraj połączeń „na próbę”
  (sprawdzanie portu, `requests.get` bez sesji, osobne sesje na operację).
  Każde nowe połączenie — także restart programu — zużywa jedno z 11 miejsc.

## Współbieżność — ile zapytań naraz (pomiar na ACB-002, 2026-09-14)

**Jedno zapytanie naraz i jedno połączenie naraz — tak samo jak ACB-001.**
Model dwudrzwiowy nie ma „drugiego kanału”.

| Test | Wynik |
|---|---|
| 10 zapytań po kolei, jedno połączenie keep-alive | OK, 0,46 s (~46 ms na zapytanie) |
| Drugie połączenie TCP, gdy pierwsze jest otwarte | `connect` przechodzi, ale **brak odpowiedzi** (timeout); w tym czasie **zawiesza się też pierwsze połączenie** — działa znowu dopiero po zamknięciu obu |
| HTTP pipelining: 2 zapytania wysłane naraz w jednym połączeniu | **brak odpowiedzi nawet na pierwsze** (timeout); po zamknięciu połączenia urządzenie działa |

Kontroler nie zrestartował się po tych testach (zegar i log bez zmian).

Wnioski:
- zapytania wysyłaj ściśle po kolei, zawsze czekając na pełną odpowiedź;
- nie łącz się z kontrolerem z dwóch miejsc naraz: przeglądarka otwarta na interfejsie
  urządzenia albo druga instancja panelu przy aktywnym połączeniu panelu zawiesza obie strony;
- jedyny sposób na przyspieszenie to mniej kroków w sekwencjach (np. mniej ponownych logowań),
  a nie równoległość.

**Ponowne połączenie tuż po zamknięciu poprzedniego (ACB-002, 2026-09-15):** proces zamknął
połączenie, a drugi proces połączył się 11 s później — TCP `connect` przeszedł, ale na
logowanie nie było odpowiedzi (timeout 12 s). Po 60 s przerwy nowe połączenie działało normalnie,
bez restartu urządzenia. Urządzenie zwalnia zamknięte połączenie z opóźnieniem, więc między
kolejnymi uruchomieniami narzędzi odczekaj około minuty.

Limitu 11 połączeń na uruchomienie na ACB-002 nie sprawdzano (test wymaga celowego
zawieszenia urządzenia). Panel i tak używa jednego trwałego połączenia.

## Język interfejsu (EN / ZH)

Urządzenie może pracować po angielsku albo po chińsku (`[Language]`, fabryczny ACB-002 — po chińsku).
**Nazwy pól i przycisków są w obu językach identyczne**; różnią się wyłącznie teksty:

| Element | EN | ZH |
|---|---|---|
| Tytuł strony logowania | `Web Controller` | `网络门禁` |
| Etykiety Configure | `Device NO`, `Driver Version`, `Users Total`, `Door Status`, `Subnet mask`, `Gateway` | `设备号`, `当前驱动版本`, `用户数`, `门状态`, `掩码`, `网关` |
| Licznik użytkowników | `Total Users: N` | `总人数: N` |
| Stronicowanie logu | `Page x Of y Page` | `第 x 页/共 y 页` |
| Status w logu | np. `... IN[#1 Door]` | np. `禁止 进门[#1号门]` (`禁止` odmowa, `远程开门` zdalne otwarcie, `进门` wejście, `出门` wyjście) |
| Wartości | `Enabled`/`Disabled`, `English`/`Chinese` | `启用`/`未启用`, `英文`/`中文` |

Wartości przycisków (`s5=Configure`, `E30=Edit` itd.) nie mają znaczenia — urządzenie
patrzy tylko na nazwę pola. Panel parsuje stronę Configure po nazwach przycisków w wierszach
tabeli (`E23` zegar, `E30+n-1` nazwa drzwi n itd.), a teksty rozpoznaje w obu językach.

**Weryfikacja na ACB-002 (2026-09-15):** ten sam kontroler odczytany po angielsku i po chińsku
daje identyczne dane (model, drzwi, status, użytkownicy, Super Card, log). Dodawanie, edycja,
wyszukiwanie i usuwanie użytkownika, auto-dodawanie oraz nazwa drzwi #2 działają też na chińskim
interfejsie. Jedyna różnica to tekst statusu w logu: angielski oryginał różni się od
tłumaczenia z ZH, więc panel sprowadza oba do jednej postaci:

| EN | ZH | Panel pokazuje |
|---|---|---|
| `Forbid IN[#1DOOR]` | `禁止 进门[#1号门]` | `Denied IN[#1 Door]` |
| `Remote Open Door IN[#2DOOR]` | `远程开门 进门[#2号门]` | `Remote Open IN[#2 Door]` |

Wpis `Remote Open` ma w kolumnie karty **adres IP, z którego przyszło otwarcie** zapisany jako liczba
(192.168.0.4 → `3232235524`), a nie numer karty. Panel zapisuje go w kopii logu z pustą kartą (od 2.7.1) —
inaczej pulpit pokazywał go w „Teraz w środku”, a czas pracy liczył jako pracownika.

**Przełączanie języka** (formularz `E17`, radio `20`: `1`=Chinese, `2`=English, zapis `S17`)
działa od razu, bez restartu; odpowiedź na zapis to strona Configure już w nowym języku.
Rozpoznanie języka: tytuł `网络门禁` na dowolnej stronie. Panel przy połączeniu
(`connect`, także z listy zapisanych) przełącza chiński interfejs na angielski
(wyłączenie: `ACS_FORCE_ENGLISH=0`). Skan sieci niczego na urządzeniach nie zmienia.

## Logowanie

```
POST /ACT_ID_1
  username=<login>&pwd=<haslo>&logId=20101222
```

Sukces = odpowiedź zawiera menu (`AddCard`, `ACT_ID_21`). Fabryczne/przykładowe
dane widoczne jako domyślne w formularzu logowania: `abc` / `654321`
(spotykane też `admin` / `admin`).

## Menu główne

```
POST /ACT_ID_21
  s1=AddCard | s2=Users | s4=Swipe | s5=Configure | s6=Exit | s7=Home
```

## Rozpoznanie modelu

Model = liczba niezależnych drzwi/przekaźników:

- liczba przycisków `UNCLOSE<n>` w menu (po zalogowaniu), lub
- liczba unikalnych `#<n> Door` na stronie Configure.

`1 → ACB-001`, `2 → ACB-002`, `4 → ACB-004`.

## Otwieranie drzwi

```
POST /ACT_ID_701
  UNCLOSE<n>=Remote Open        # n = numer drzwi (1..liczba_drzwi)
```

## Użytkownicy / karty

### Lista
```
POST /ACT_ID_21   s2=Users
```
Tabela: `User ID | Card NO | Name | Operation`. W kolumnie Operation przyciski
`E<row>` (Edit) i `D<row>` (Delete), gdzie `<row>` to wewnętrzny indeks slotu
(NIE User ID i NIE pozycja na stronie).

### Wyszukiwanie
```
POST /ACT_ID_21    s2=Users                          # kontekst listy - WYMAGANY
POST /ACT_ID_323   US21=<fraza>&22=0&23=&24=Search
```
Wysłane od razu po logowaniu (urządzenie na stronie Home) jest ignorowane: wraca strona
Home, bez wyników. Szuka po fragmencie numeru karty albo nazwy.

Lista ma stronicowanie (20 wierszy): `POST /ACT_ID_325` z ukrytymi `PC` (np. `00001`),
`PE` (`00020`) i przyciskami `PF`/`PP`/`PN`/`PE`. Panel 2.0.0 odsyła ukryte pola z bieżącej strony
i przycisk `PN` (jak przeglądarka), aż zbierze wszystkich użytkowników; karty, których nadal brakuje
(numery z UDP `0x58`/`0x5C`), dociąga wyszukiwarką. Edycja/usuwanie użytkownika spoza pierwszej strony:
`ACT_ID_323` (wyszukiwarka po numerze karty), potem `E<row>`/`D<row>` z wyników.
**Sprawdzone na sprzęcie 2026-09-18** (ACB-002, 25 kart) — szczegóły w „Panel 2.0.0” niżej: strony liczą sloty,
a nie osoby, i „Next” za ostatnią stroną powtarza ostatnią stronę.

### Dodanie karty (ręcznie)
```
POST /ACT_ID_312   AD21=<nr_karty>&AD22=<nazwa>&25=Add
```
Odpowiedź zawiera `Add Successfully`.

### Numer nadrukowany na karcie a numer w kontrolerze (Wiegand-26) — sprzęt 2026-09-18

Czytnik 13,56 MHz **nie przekazuje numeru karty wprost**. Wysyła 24 bity rozbite na kod obiektu
(`FC`, 8 bitów) i numer karty (`CN`, 16 bitów), a kontroler skleja je z powrotem **dziesiętnie**,
tak jakby `CN` miało zawsze 5 cyfr:

```
N24 = numer_na_karcie & 0xFFFFFF     # starsze bity są obcinane
FC  = N24 >> 16                      # 0–255
CN  = N24 & 0xFFFF                   # 0–65535
numer w kontrolerze = FC * 100000 + CN
```

Pomiary na ACB-002 (kontroler „test 2 drzwiowy”, rekordy 227–228 i dalsze):

| numer na karcie | FC | CN | w kontrolerze |
|---|---|---|---|
| 10000 | 0 | 10000 | 10000 |
| 12345 | 0 | 12345 | 12345 |
| 99999 | 1 | 34463 | 134463 |
| 100000 | 1 | 34464 | 134464 |
| 999999 | 15 | 16959 | 1516959 |
| 16777216 | 0 | 0 | **brak zdarzenia w logu** (karta „zerowa”) |

Ostatni wiersz rozstrzyga szerokość `FC`: gdyby pole miało 16 bitów (Wiegand-34), `16777216`
dałoby `25600000`. Brak wpisu — identyczny jak przy karcie z samymi zerami — dowodzi obcięcia do 24 bitów.

Wnioski:

- Numery **do 65535** są identyczne po obu stronach.
- Wyżej numery przeskakują; odwzorowanie jest różnowartościowe, ale **nieciągłe** — numer, w którym pięć
  ostatnich cyfr wypada w 65536–99999 (np. `170000`), nie zostanie zgłoszony przez żadną kartę.
- Zakres użytecznych numerów kart to **1 – 16 777 215**, najwyższy możliwy numer w kontrolerze to `25565535`.
  Numery różniące się o wielokrotność `16777216` są dla kontrolera nie do odróżnienia, a same wielokrotności
  dają kartę `0`, której kontroler nie rejestruje.
- Wzór odwrotny (numer z logu → nadruk na karcie): `(X // 100000) * 65536 + X % 100000`, o ile `X % 100000 ≤ 65535`.

Panel liczy to w obie strony: `wg_read()` / `wg_card()` / `card_warning()` w `acs_panel.py` i ich odpowiedniki
w JS (`wgRead` / `wgCard` / `cardWarn`) — podpowiedź pod polem „Numer karty”, przelicznik w zakładce
„Pracownicy i karty” i przeliczenie pod kursorem przy numerach w tabeli kart i w logu przejść.

### Auto-dodawanie przez przyłożenie karty
```
POST /ACT_ID_21    s1=AddCard
POST /ACT_ID_314   A1=Auto Add by Swiping           # -> strona potwierdzenia
POST /ACT_ID_314   Y1=Confirm Auto AddCard By Swiping
```
Po tym kontroler czeka na przyłożenie karty do czytnika.

### Edycja użytkownika: nazwa i uprawnienia do drzwi
```
POST /ACT_ID_21    s2=Users                          # ustaw kontekst listy
POST /ACT_ID_324   E<row>=Edit                        # -> formularz
POST /ACT_ID_324   USX<row>=<nazwa>&24=<0|1>&25=<0|1>&26=<0|1>&27=<0|1>&S<row>=Save
```
Formularz (potwierdzony na ACB-004): kolumna `开门权限` / uprawnienia — lista `24` = drzwi #1,
`25` = #2, `26` = #3, `27` = #4, wartości `0` (`禁止`, zakaz) / `1` (`允许`, dostęp).
Nowo dodana karta ma dostęp do wszystkich drzwi. Numer karty jest stały.
Bieżące uprawnienia da się odczytać tylko z tego formularza (lista użytkowników ich nie pokazuje).
**Zapis nadpisuje wszystkie cztery pola** — trzeba odesłać bieżące wartości drzwi, których nie
zmieniamy (wcześniejsza wersja panelu wysyłała `24..27=1` i każda zmiana nazwy przywracała
pełny dostęp). Panel odsyła pola w kolejności formularza i sprawdza zapis ponownym odczytem.

### Usunięcie użytkownika (dwustopniowe)
```
POST /ACT_ID_21    s2=Users                          # ustaw kontekst listy
POST /ACT_ID_324   D<row>=Delete                      # -> strona potwierdzenia
POST /ACT_ID_324   X<row>=OK                          # UWAGA: X<row>, nie X1!
```
Przycisk potwierdzenia to `X<row>` z tym samym numerem co `D<row>`.

## Log przejść (Swipe)

```
POST /ACT_ID_21    s4=Swipe                           # kontekst logu
POST /ACT_ID_345   PC=<pozycja>&PE=0&PF=First | PP=Prev | PN=Next | PE=Last | PF=Refresh
```
Formularz stronicowania ma ukryte pola `PC` (pozycja bieżącej strony, np. `146`)
i `PE=0` — trzeba je wysłać razem z przyciskiem (tak robi przeglądarka). Bez `PC`
urządzenie przechodzi na ostatnią stronę. Strona ma 20 rekordów, najnowsze na stronie 1.
Wiersze `<tr class=Y>` (dozwolone, zielone) / `<tr class=N>` (odmowa/zdarzenie,
żółte). Kolumny: `Record ID | Card NO | Name | Status | DateTime`.
Nagłówek zawiera `Page <x> Of <y> Page`.

**Logu nie da się wyczyścić** (ACB-002, V6.62.51215, sprawdzone 2026-09-21): strona Swipe ma tylko
nawigację (`PS`/`PF`/`PP`/`PN`/`PE`), Configure — `Reboot`, `Adjust Time` i edycje pól z tabeli niżej,
bez „Clear/Delete records”. `E24` tylko włącza/wyłącza zapis zdarzeń drzwi i przycisku, nie kasuje logu.
**Reset stykami (2026-09-21) też go nie czyści**: przywraca IP `192.168.0.0` i konto `abc/654321`,
a log (numeracja ciągła: 249–251 = `Reboot` przy resecie, 252 = odbicie karty), karty (Users Total 4),
nazwy i czasy otwarcia drzwi zostają.
Dlatego „Czyszczenie logów” w panelu (2.6.0) usuwa tylko kopię w bazie panelu i zapamiętuje granicę
(`sync_state.cleared_to`), sprzed której pobieranie logu pomija wpisy.

## Konfiguracja (Configure → ACT_ID_355)

Wzorzec: wejść w tryb edycji danego pola (`E<xx>=Edit`), potem zapisać
(`S<xx>=Save`). Wszystko przez `POST /ACT_ID_355`, po uprzednim wejściu w
Configure (`POST /ACT_ID_21 s5=Configure`).

| Pole | Wejście | Zapis | Parametry |
|---|---|---|---|
| Nazwa drzwi #1 | `E30` | `S30` | `COXDOOR21=<nazwa>` |
| Nazwa drzwi #2 | `E31` | `S31` | `COXDOOR21=<nazwa>` (to samo pole) |
| Czas otwarcia drzwi #1 (s) | `E40` | `S40` | `COXDELAY21=<0..255>` |
| Czas otwarcia drzwi #2 (s) | `E41` | `S41` | `COXDELAY21=<0..255>` |
| Hasła otwarcia drzwi #1 (4 sloty) | `E50` | `S17`/`S18`/`S19`/`S20` | `PWD1`..`PWD4` (do 6 cyfr), `DESC1`..`DESC4` |
| Hasła otwarcia drzwi #2 (4 sloty) | `E51` | `S21`/`S22`/`S23`/`S24` | `PWD5`..`PWD8` (do 6 cyfr), `DESC5`..`DESC8` |
| Rejestr zdarzeń | `E24` | `S24` | `20=1` (Enabled) / `20=2` (Disabled) |
| Super Card (2 sloty) | `E25` | `S33`/`S34` | `PWD1`/`PWD2` (do 19 cyfr) |
| Sieć (IP/brama) | `E12` | `S12` | `COXIP21..24`=IP, `COXIP26..29`=brama, `COXHTTPPORT=80`; na ACB-002 także ukryte `20` (tryb IP, `2`=stały) i lista `25` (maska: `0`=/24, `1`=/16) — panel odsyła je z bieżącymi wartościami **w kolejności formularza** (patrz niżej) |
| Konto administratora | `E13` | `S13` | `COXOP21`=stary login, `COXOP22`=stare hasło, `COXOP23`=nowy login, `COXOP24`/`COXOP25`=nowe hasło (×2) |
| Język | `E17` | `S17` | `20=1` (Chinese) / `20=2` (English) |
| Restart | `E16=Reboot` | `Reboot=Reboot` | `E16` otwiera tylko stronę „Please Confirm!” (anulowanie: `C1`) — restart dopiero po `Reboot` |
| Ustawienie zegara | `E23` | `S23` | `21`=rok, `22`=miesiąc, `23`=dzień, `24`=godzina, `25`=minuta (listy), `26`=sekundy (ukryte, domyślnie `00`) |

> Schemat dla drzwi n: nazwa `E/S<29+n>`, czas otwarcia `E/S<39+n>`, hasła `E<49+n>` ze slotami
> `PWD<4(n-1)+1..4n>` i zapisem `S<16+indeks_PWD>`. Potwierdzone na sprzęcie dla wszystkich drzwi:
> #1 (ACB-001, ACB-002, ACB-004), #2 (ACB-002, ACB-004), #3–#4 (ACB-004: `E32`/`E33`, `E42`/`E43`,
> `E52` = `PWD9..12`/`S25..S28`, `E53` = `PWD13..16`/`S29..S32`; zapis nazwy i czasu sprawdzony
> odczytem). Kody `S17`, `S23`, `S24`, `S33` występują w kilku formularzach (hasła / język,
> zegar, zdarzenia, nazwa drzwi #4 / Super Card) — urządzenie rozróżnia je po stronie otwartej
> wcześniej przez `E<xx>`.
>
> Fabryczny log ACB-004 zawiera dla każdych drzwi tylko zdarzenia wejścia (`IN`), bez `OUT` —
> liczby czytników na ACB-004 nie potwierdzono.
>
> Na ACB-002 każde drzwi mają 2 czytniki (wejście i wyjście), razem 4, ale jeden przekaźnik;
> log przejść podaje drzwi i kierunek (`进门` / `出门`). Formularz `E13` (konto administratora)
> zawiera w ukrytych polach `COXOP21`/`COXOP22` **obecny login i hasło otwartym tekstem**.

### Zmiana adresu IP (zweryfikowane na ACB-002, 2026-09-15)

Formularz `E12` (ACB-002): `MAC Address` (tylko odczyt), ukryte `20=2`, `COXIP21..24`, lista `25`
(maska), `COXIP26..29`, ukryte `COXHTTPPORT=80`, przyciski `S12`/`C12`.

1. **Kolejność pól ma znaczenie** — firmware czyta je po kolei. Wysłanie
   `20, COXIP21..24, COXIP26..29, COXHTTPPORT, 25, S12` (maska na końcu) urządzenie odrzuca
   komunikatem **`HTTP PORT invalid!`** na stronie Configure (HTTP 200, bez zmian). Kolejność
   z formularza `20, COXIP21..24, 25, COXIP26..29, COXHTTPPORT, S12` jest przyjmowana.
2. Przyjęty zapis zwraca `[Configure]->[Edit] Successfully. Please Reboot the device` —
   **nowy adres działa dopiero po restarcie**; do tego czasu urządzenie zostaje pod starym IP,
   a zapisany adres czeka (wejdzie przy dowolnym następnym restarcie).
3. Restart (`E16` → `Reboot=Reboot`) trwa ok. 5 s, potem kontroler odpowiada pod nowym IP.

Panel robi zapis, sprawdza komunikat, restartuje urządzenie i przełącza aktywne połączenie
na nowy adres (test: .123 → .124 → .123, oba kroki OK).

## Wyszukiwanie w sieci (skan)

1. Autodetekcja podsieci (lokalny IP → `/24`).
2. Skan **całego** zakresu, włącznie z adresem sieci (`.0`) i broadcast (`.255`)
   — kontroler może być ustawiony na dowolnym adresie.
3. Dla każdego adresu: sprawdzenie portu 80 z **ponawianiem** (kontroler
   jednowątkowy gubi pojedyncze pakiety SYN pod obciążeniem skanu).
4. Potwierdzenie „to kontroler": `GET /` zawiera `Web Controller` oraz `ACT_ID_1`.
5. Rozpoznanie modelu: logowanie (podane dane, w razie niepowodzenia fabryczne
   `admin/admin`, `abc/654321`) → liczba drzwi → model.

### Zegar urządzenia
`E23=Adjust Time` **nie synchronizuje czasu** — otwiera formularz ustawienia daty
i godziny (wypełniony obecnym czasem kontrolera). Zmiana następuje dopiero po
wysłaniu `S23=Save` z polami `21`–`26`. Panel wypełnia je czasem serwera (NTP);
jeśli urządzenie ignoruje sekundy, zapis wykonywany jest na początku pełnej minuty.

### Super Card i hasła otwarcia — odczyt
Formularze `E25` (Super Card) i `E50` (hasła otwarcia drzwi #1) zawierają osobny
`<form>` na każdy slot: ukryte `DESC<n>` oraz `PWD<n>`.

- **Super Card**: `<input type='text' name=PWD<n> value='<numer>'>` — bieżąca
  wartość jest odczytywalna (także karty ustawione przed użyciem panelu).
  Panel po zapisie ponownie otwiera formularz i sprawdza wartość.
- **Hasła otwarcia**: `<input type=password name=PWD<n>>` **bez atrybutu value** —
  urządzenie nie ujawnia haseł; nie da się ustalić, czy slot jest zajęty.
  Można je tylko nadpisać lub wyczyścić (pusta wartość + `S17`..`S20`).
  **ACB-002 (V6.62, 2026-09-17) jednak zwraca hasła** w formularzu `E51` (drzwi #2, slot 1
  zajęty) — zależne od firmware. Od 1.7.0 panel nie wysyła kodów do przeglądarki: `/api/codes`
  zwraca tylko `true`/`false` (zajęty slot), `/api/status` liczbę zapisanych Super Card.
- Długości (atrybut `maxlength` formularzy): hasło otwarcia **6 cyfr**, Super Card **19 cyfr**
  (numer karty w protokole WG to uint32, więc realnie do 4294967295). PIN karty w `0x50`
  zajmuje 3 bajty; uhppoted sprawdza PIN tylko gdy `< 1000000`, czyli też do 6 cyfr.

### Otwarcie hasłem z klawiatury — log
WWW: `Super Password Open Door[#2 Door]`, bez numeru karty. UDP `0xB0` (rekord 85, ACB-002,
2026-09-17 11:46:56): typ `2`, przyjęte, drzwi `2`, kierunek `1`, **kod powodu `25`**, pole karty
**`10`**. Użytkownik: hasło w slocie 1 drzwi #2 to NIE `10`, a inne sloty drzwi #2 były puste
w chwili odczytu (hasła mogły być zmieniane wcześniej).
**Test 2026-09-17 12:13 (drzwi #2, slot 2 = 111111, slot 3 = 222222): rekord 88 = hasło ze slotu 3,
rekord 89 = hasło ze slotu 2 — oba rekordy (i 85–87) są IDENTYCZNE bajt w bajt poza czasem**
(typ 2, powód 25, pole karty `10`). Kontroler NIE zapisuje, którym hasłem otwarto drzwi —
z logu (WWW ani UDP) nie da się zidentyfikować hasła ani grupy.
Obserwacje użytkownika z tego testu: **błędne hasła nie trafiają do logu w ogóle** (ani odmowa,
ani liczba prób), a **hasła nie zatwierdza się klawiszem** — przekaźnik zadziałał od razu po
ostatniej cyfrze 111111. Bufor cyfr: przerwa 2–3 s między cyframi nie przerywa wpisywania
(`111` + pauza + `111` otwiera), dłuższa przerwa zeruje wpisane cyfry (dokładny czas nieznany).
**Brak „ruchomego okna”**: `52111111` i `96222222` (poprawne hasło poprzedzone innymi cyframi)
nie otwierają — kontroler nie porównuje ostatnich cyfr, próba zaczyna się od nowa. Nadal brak
blokady po błędach i śladu w logu.
Hasła różnej długości (2026-09-17, slot 1 = `4444`, slot 2 = `123456`): 6 cyfr otwiera od razu po
ostatniej cyfrze, 4 cyfry — z opóźnieniem ok. 1 s (kontroler czeka, czy nie będzie kolejnych cyfr);
`54444` nie otwiera. Niesprawdzone: hasło będące początkiem innego (np. `4444` i `444412`).

Wyjście z formularza bez zapisu: `POST /ACT_ID_21 s5=Configure`.

## Kanał UDP 60000 (protokół WG) — rozpoznanie 2026-09-15, tylko odczyt

Kontrolery ACB to sprzęt WG (Weigeng): numer urządzenia zaczyna się od liczby drzwi (1…/2…/4…),
firmware „Web Controller” V6.62. Odpowiadają na „krótkie pakiety” WG — 64 bajty:
`[0]=0x17`, `[1]=funkcja`, `[4..7]=nr urządzenia (uint32 LE)`, `[8..39]=dane`, `[40..43]=nr kolejny`.
Daty i godziny w BCD. UDP nie zużywa limitu 11 połączeń TCP.

Sprawdzone na ACB-002 (200000002, 192.168.1.100), wyłącznie odczyt:

| Funkcja | Zapytanie | Odpowiedź |
|---|---|---|
| `0x94` wyszukiwanie | broadcast, nr urządzenia 0 | nr, IP, maska, brama, MAC, wersja `0662`, data `20151215` |
| `0x96` zmiana adresu | broadcast, nr urządzenia; `[0..3]` IP, `[4..7]` maska, `[8..11]` brama, `[12..15]` `55 AA AA 55` | wg protokołu WG brak odpowiedzi — panel sprawdza nowy adres ponownym `0x94` (2.5.0, „Ustaw adres IP”); **jeszcze nie sprawdzone na sprzęcie** |
| `0x32` zegar | — | `20 26 09 15 17 36 25` = 2026-09-15 17:36:25 |
| `0x58` liczba uprawnień | — | `1` |
| `0x5C` uprawnienie nr N | N (uint32 LE) | karta `87 d6 12 00` = 1234567, od `20110101`, do `20291231`, drzwi 1..4 = `01 00 01 01`, PIN (3 bajty) |
| `0x98` strefa czasowa nr N | N (1 bajt) | nr 2 i 3: same zera (nieustawione) |

Bajt dostępu do drzwi w uprawnieniu WG: `0` zakaz, `1` zawsze, `2..254` = numer strefy czasowej.

**Strefy czasowe — test na sprzęcie 2026-09-16 (ACB-002, karta 1234567, drzwi #1): DZIAŁAJĄ.**

| Funkcja | Dane | Wynik |
|---|---|---|
| `0x88` zapis strefy | `[0]`=nr (2..254), `[1..4]` od `YYYYMMDD`, `[5..8]` do, `[9..15]` pn..nd (`1`=tak), `[16..19]` przedział 1 `HHMM`–`HHMM`, `[20..27]` przedziały 2–3, `[28]` strefa powiązana | zapisuje się, odczyt `0x98` zgodny |
| `0x50` zapis uprawnienia | `[0..3]` karta LE, `[4..11]` daty od/do, `[12..15]` drzwi 1..4, `[16..18]` PIN | zapisuje się, odczyt `0x5A` zgodny |
| `0x5A` uprawnienie po numerze karty | `[0..3]` karta | jak `0x5C` |
| `0x20` stan | — | `[0..3]` nr ostatniego rekordu, `[4]` typ, `[5]` przyjęte, `[6]` drzwi, `[7]` 1=wejście/2=wyjście, `[8..11]` karta, `[12..18]` czas BCD, `[19]` kod powodu |
| `0xB0` rekord logu nr N | `[0..3]` N | układ jak `0x20` |

Kody powodu z logu: `1` przyjęte, `6` brak uprawnienia do drzwi (bajt `0`, odrzuca wejście i wyjście),
`15` poza strefą czasową. Przebieg testu (rekordy 20–22): strefa 03:00–04:00 → wejście o 10:57:55
**odrzucone, kod 15**; po przełączeniu strefy na 00:00–23:59 wejście o 10:58:00 przyjęte.
**Strefa czasowa obejmuje oba czytniki drzwi** — test 2026-09-16 11:06–11:07 (strefa kończąca się
5 min wcześniej, bez przełączania w trakcie): wyjście **odrzucone, kod 15** (rekordy 23, 25), wejście
odrzucone, kod 15 (24, 26). Bajt uprawnienia jest jeden na drzwi, a dostępna dokumentacja WG nie ma opcji
„wyjście bez ograniczeń czasowych”. Scenariusz „wejście do 18:00, wyjście po 18:00” wymaga pomocy
komputera: nasłuch zdarzeń (`0x90` adres odbiorcy) i zdalne otwarcie (`0x40`) po odrzuconym wyjściu z kodem 15
albo tryb sterowania z komputera (w uhppoted `set-pc-control`: kontroler oddaje decyzje hostowi, bez kontaktu
przez 30 s wraca do lokalnej listy kart). Oba niesprawdzone. Zapis strefy samymi zerami (próba „wyczyszczenia”) nie
działa — strefa nr 2 została na kontrolerze jako 00:00–23:59 codziennie (żadna karta jej nie używa).
Uwaga: formularz WWW użytkownika (listy `24..27`) zna tylko `0`/`1` — przy strefie ≥2 żadna opcja
nie jest zaznaczona, więc zapis z WWW (i obecne `edit_user` panelu) nadpisałby strefę.
Karty mają ważność do 2029-12-31 (domyślne `0x5C` od WWW) — zmiana możliwa tylko przez UDP.


### Ograniczenie tylko wejścia — rozpoznanie 2026-09-16

Źródło: projekt open source uhppoted (kontrolery UHPPOTE = ten sam protokół WG); jego symulator firmware
ma kody powodów zgodne z naszym sprzętem (`0x06` brak uprawnienia, `0x0F` poza strefą czasową).
W symulatorze strefa czasowa jest sprawdzana bez względu na kierunek odbicia — kierunek ma znaczenie tylko
dla PIN-u z klawiatury. Kandydat na „wejście do 18:00, wyjście zawsze”: **lista zadań** kontrolera.

| Funkcja | Dane (od bajtu 8) |
|---|---|
| `0xA6` wyczyść listę zadań | `55 AA AA 55` |
| `0xA8` dodaj zadanie | od `YYYYMMDD`, do `YYYYMMDD`, pn..nd (7× `0/1`), start `HHmm`, drzwi, typ, „więcej kart” |
| `0xAC` zatwierdź (odśwież) listę | `55 AA AA 55` |
| `0xA4` klawiatury czytników 1..4 | 4× `0/1` |

Typy zadań: `0` drzwi sterowane, `1` otwarte na stałe, `2` zamknięte na stałe, `3` wyłącz strefy czasowe,
`4` włącz strefy, `5` karta bez PIN, **`6` karta + PIN na wejściu**, `7` karta + PIN na wejściu i wyjściu,
`8`/`9` więcej kart, `10` jednorazowe otwarcie, `11` wyłącz przycisk, `12` włącz przycisk. Kod powodu
`0x07` = zły/brak PIN. Pomysł: codziennie 18:00 zadanie `6`, 10:00 zadanie `5` — czytnik wejścia bez
klawiatury nie dostanie PIN-u (odmowa), czytnik wyjścia działa. Do sprawdzenia: czy sprzęt tak robi,
czy obejmuje karty bez PIN-u (panel WWW nadaje domyślny PIN 345678), czy po restarcie kontrolera
w trakcie dnia zadanie się odtwarza (symulator nadrabia zadania z minionych godzin).

**Test na sprzęcie 2026-09-16 13:57 (ACB-002, drzwi #1, karta 1234567 z PIN-em 345678, czytnik bez klawiatury):
DZIAŁA.** Zadanie typu `6` od bieżącej minuty: wyjście 13:57:10 przyjęte (kod 1), wejście 13:57:19
**odrzucone, kod 7** (zły/brak PIN). Po zadaniu typu `5` wejście 13:57:24 przyjęte. Uprawnienie karty
bez zmian przez cały test. Zadanie zadziałało od razu po `0xAC` (w tej samej minucie).
Niewyjaśnione rekordy 27–36 (13:33–13:34, ta sama karta): wyjścia odrzucane kodem 15, wejścia przyjmowane —
nie pochodzą ze skryptów panelu; do ustalenia z użytkownikiem.

**Panel 1.2.0 — „Godziny wejścia”** (`entry_hours_tasks()`): przy zapisie `0xA6` → zadania `0xA8` → `0xAC`.
Dla drzwi z ograniczeniem: `6` o 00:00 (dni bez wejścia oraz dni z wejściem, gdy „od” > 00:00), `5` o „od”
i `6` o „do” (dni z wejściem), zadania od dziś do 2099-12-31; dla każdych drzwi zadanie „na teraz”
(zakres dat = dziś, bieżąca minuta zegara kontrolera `0x32`) z typem właściwym dla tej chwili — także `5`
dla drzwi bez ograniczeń, bo tryb PIN zostaje w kontrolerze po wyczyszczeniu listy. Logika sprawdzona
symulacją tygodnia (stan co 7 min zgodny z konfiguracją) i na symulatorze UDP; na sprzęcie — pojedyncze
zadania `5`/`6` (test 13:57). Zanik zasilania listy zadań nie kasuje — po restarcie kontrolera (2026-09-17 17:08)
godziny wejścia działały dalej bez ponownego zapisu z panelu.

**Panel 1.3.0 — wyjątek „wejście o każdej porze”** (per dział): lista zadań działa per drzwi, więc wyjątek
realizuje panel — odpytuje `0x20` co 0,5 s (ciche, bez wpisów w dzienniku urządzenia), zaległe rekordy czyta
`0xB0`, a po odmowie typu 1 (karta), kierunek 1 (wejście), kod `0x07`, dla karty z działu z wyjątkiem i drzwi
z ograniczeniem wysyła `0x40` (`[8]` = nr drzwi, odpowiedź `[8]` = 1). Symulator uhppoted sprawdza PIN
PRZED uprawnieniem do drzwi, więc panel przed otwarciem czyta `0x5A` i otwiera tylko przy bajcie drzwi = 1.
Odpytywanie co 0,2 s. **Sprzęt 2026-09-16 17:54–17:55 (ACB-002, karta 7654321): działa** — odmowa kod 7,
w tej samej lub następnej sekundzie rekord otwarcia `0x40` (karta 4000000001, kod 44).

**Kandydat na wyjątek w pamięci kontrolera: PIN karty = 0.** W symulatorze uhppoted sprawdzenie PIN-u jest
pomijane dla `card.PIN == 0` (`if card.PIN != 0 && card.PIN < 1000000`). Karty z WWW mają PIN 345678.
Zapis PIN-u: `0x50` z bajtami `[0..15]` z odczytu `0x5A` i nowym `[16..18]`.
**Sprzęt 2026-09-17 10:55 (ACB-002, drzwi #1 w trybie `6`): DZIAŁA** — karta 157920 z PIN-em 0 przyjęta (kod 1),
karta 1234567 z PIN-em 345678 odrzucona kodem 7. Panel 1.3.0 ustawia PIN-y sam (`entry_pins_sync`).
Lista uprawnień: `0x58` podaje liczbę BEZ usuniętych slotów (karta `FF FF FF FF` w `0x5C`), koniec listy = karta 0.

**Panel 1.8.0 — godziny wejścia per dział.** Lista zadań ustawia tryb per drzwi, a strefa czasowa karty blokuje
też wyjście, więc różne godziny działów na tych samych drzwiach (np. biuro 8–16, magazyn 6–22, serwis 22–6)
w samym kontrolerze nie mają rozwiązania z wolnym wyjściem. Panel trzyma drzwi z ograniczeniem stale w trybie `6`
(zadanie codziennie 00:00 + „na teraz”) i przełącza PIN-y kart: w godzinach działu PIN 0, poza nimi 345678.
Kolejność przy zapisie: najpierw PIN-y (`0x50`), potem lista zadań — grupa w swoich godzinach nie traci wejścia.
Na symulatorze UDP (zegar przestawiany na granice godzin) przełączenia następują w ciągu ~2 s od granicy.
Bez działającego panelu PIN-y się nie zmieniają. Dlatego przy **jednej zmianie** (wszystkie działy z kartami
mają te same godziny albo „o każdej porze”) panel zapisuje zamiast tego zadania `5`/`6` o 00:00, „od” i „do”
(dni tygodnia liczone z godzin, także przez północ) i stały PIN 0 tylko działom „o każdej porze” — wtedy godziny
działają w samym kontrolerze, jak w 1.2.0. Do sprawdzenia na sprzęcie: przełączenie na granicy godzin
i czy częste zapisy `0x50` nie szkodzą pamięci kontrolera (kilka zapisów na kartę dziennie).

## Panel 2.0.0 — ważność, blokady, zdarzenia

Testy na sprzęcie 2026-09-17/18 (ACB-002 nr 200000002, V6.62, drzwi #1, karta 1234567).

- **Ważność karty**: `0x5A` → zmiana bajtów `[4..11]` (od/do, BCD `YYYYMMDD`) → `0x50` → odczyt `0x5A` musi się
  zgadzać co do karty, dat, drzwi i PIN-u. Własna strona kontrolera zna lata 2011–2029 (lista roku w „Adjust Time”),
  karty dodane stroną mają `20110101`–`20291231`. **Kod powodu odmowy po dacie „do” to `15`** — ten sam, co „poza
  strefą czasową”, na wejściu i na wyjściu (rekordy 155–156, data „do” ustawiona na wczoraj). Dokumentacyjnego
  kodu `13` ten firmware nie używa, więc po samym logu nie da się odróżnić przeterminowanej karty od strefy czasowej.
  Odmowa przed datą „ważna od” — niesprawdzona.
- **Blokada**: te same kroki z bajtami drzwi `[12..15]` = `0`; kontroler odrzuca kartę kodem `6` na wejściu
  i na wyjściu (rekordy 161–162). Po przywróceniu bajtów karta znów wchodzi (kod `1`).
- **Zapis użytkownika stroną WWW** (`ACT_ID_324`) **zawsze** nadpisuje daty uprawnienia fabrycznymi
  (`20110101`–`20291231`) — sprawdzone zmianą samej nazwy. Przy okazji ustawia bajty drzwi `[14]` i `[15]`
  (drzwi #3–#4) na `1`, choć kontroler ma dwoje drzwi. Panel czyta `0x5A` przed i po zapisie i przywraca daty
  (`0x50`); bajtów drzwi #3–#4 nie cofa (na dwudrzwiowym kontrolerze nie mają znaczenia).
- **Stronicowanie listy Users** (`ACT_ID_325`, 25 kart): kolejne strony formularzem z ukrytymi `PC`/`PE`
  i przyciskiem `PN` oddają komplet. Strony liczą **sloty, nie osoby** — slot po skasowanym użytkowniku zostaje
  pusty, więc strona 1 miała 19 wierszy, a strona 2 sześć. „Next” za ostatnią stroną zwraca wciąż tę samą stronę
  (formularz dalej podaje `PN`), więc pętla musi przerywać na braku nowych wierszy. `E<row>`/`D<row>` z wyników
  wyszukiwarki działają dla użytkowników spoza pierwszej strony.
- **Zdarzenia na żywo**: `0x20` co 1 s, brakujące rekordy `0xB0` (najwyżej 50 wstecz). Typ `1` odbicie karty,
  `2` drzwi/przycisk/otwarcie z komputera (numer karty w tych zdarzeniach nie jest kartą — sprzęt wpisuje `1`
  przy przycisku, `8` przy otwarciu, `9` przy zamknięciu, `10` przy haśle), `3` alarm. Kody potwierdzone
  na sprzęcie: `1` przyjęta, `6` brak uprawnienia, `7` brak PIN-u, `15` strefa czasowa / ważność, `20` przycisk
  wyjścia, `23`/`24` drzwi otwarte / zamknięte, `25` hasło, `44` otwarcie z komputera. Zwarcie zacisku czujnika
  daje kilka przełączeń `23`/`24` w tej samej sekundzie (drgania styku).
- **Czas otwarcia drzwi liczy panel** (2.1.0, `_door_check`): zdarzenie `23` zaczyna otwarcie, `24` je kończy,
  a stan wyznacza **numer rekordu**, nie stempel czasu (drgania styku dają kilka `23`/`24` w tej samej sekundzie,
  czasem z rekordami zapisanymi „nie po kolei” — rekordy 215–219 z 2026-09-17 17:47:43–44). Po połączeniu panel
  szuka stanu pilnowanych drzwi w 60 ostatnich rekordach (`0xB0`), a gdy ich tam nie ma — w swoim zapisie.
- **Alarmów (typ 3) ten firmware nie zapisuje.** Rozwarcie czujnika drzwi bez odbicia karty (wymuszone otwarcie)
  dało tylko kod `23`; drzwi „otwarte” ponad 3,5 min po odbiciu nie dały kodu `37`. Strona WWW nie ma ustawień
  alarmów poza `Record PushButton And DoorStatus Events`.
- **Włączenie zasilania nie daje kodu `28`.** Kontroler zapisał pusty rekord (same zera, bez czasu) i po jednym
  zdarzeniu `23` na każde drzwi, bo niepodłączone wejście czujnika czyta się jako „otwarte”. Panel pomija rekordy
  bez czasu (`_live_loop`).
- **Pojemność listy zadań: 204.** 205. zadanie `0xA8` odrzuca (odpowiedź `0`), zarówno przed `0xAC`, jak i po
  zatwierdzeniu pełnej listy. Jedno zadanie zapisuje się ok. 0,26 s (204 zadania to ~55 s). 204. zadanie naprawdę
  działa: ostatnim wpisem był tryb `6` „na teraz” dla drzwi #1, a odbicie zaraz po `0xAC` zostało odrzucone kodem `7`.
  Ponieważ zapis zaczyna się od `0xA6` (czyszczenie), panel liczy zadania przed czyszczeniem (`entry_tasks_fit`,
  `WG_TASKS_MAX`) i odrzuca za dużą konfigurację, nie ruszając kontrolera — sprawdzone na sprzęcie: przy 206
  zadaniach poszło tylko zapytanie o zegar.
- **Lista zadań przeżywa zanik zasilania**: po restarcie kontrolera godziny wejścia działały dalej (karta przyjęta
  w oknie godzin, bez ponownego zapisu z panelu).
- **Lista zadań z wyjątkami w kalendarzu**: symulator uhppoted wykonuje zadania o tej samej minucie w kolejności
  z listy (ostatnie wygrywa); panel i tak nie zapisuje dwóch zadań o tej samej minucie dla tych samych drzwi
  z różnymi datami obowiązywania (zakresy dat zadań tygodniowych omijają dni z wyjątkami). Każdy osobny dzień
  wyjątku dzieli zadania tygodniowe na kolejne zakresy dat — przy dwojgu drzwiach limit 204 wypada koło 11–12
  osobnych dni (święta ustawowe na rok naprzód to ok. 112 zadań na jedne drzwi).

**Wyszukiwanie `0x94` a kontroler spoza podsieci (2026-09-21, ACB-002 nr 200000002):** kontroler z adresem
192.168.50.0/24 (serwer 192.168.1.10/24) odpowiada na rozgłoszeniowe `0x94` — w odpowiedzi podaje swój adres,
choć pakiet przychodzi z innym adresem źródłowym (tu 192.168.1.20). Odpowiedzi nie da się więc przypisać po adresie
nadawcy — tylko po numerze urządzenia z bajtów `[4..7]`. HTTP i UDP unicast do takiego kontrolera nie działają
(ARP `INCOMPLETE`), zmiana adresu `0x96` musi iść rozgłoszeniowo.
