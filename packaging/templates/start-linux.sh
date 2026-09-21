#!/bin/sh
# Spreest - Panel ACB (kontrola dostępu) - start na Linuksie
{{MODE_ENV}}DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
# uruchomiony dwuklikiem bez terminala - otwórz terminal, żeby było widać okno panelu
if [ ! -t 1 ] && [ -z "$ACB_IN_TERMINAL" ] && { [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; }; then
  export ACB_IN_TERMINAL=1
  for t in x-terminal-emulator gnome-terminal konsole xfce4-terminal mate-terminal xterm; do
    if command -v "$t" >/dev/null 2>&1; then
      case "$t" in
        gnome-terminal) exec "$t" -- "$0" ;;
        *) exec "$t" -e "$0" ;;
      esac
    fi
  done
fi
case "$(uname -m)" in
  x86_64|amd64) PY="$DIR/runtime/linux-x64/bin/python3" ;;
  aarch64|arm64) PY="$DIR/runtime/linux-arm64/bin/python3" ;;
  *) echo "Nieobsługiwany procesor: $(uname -m)"; exit 1 ;;
esac
if [ ! -x "$PY" ]; then
  echo "Nie znaleziono $PY - rozpakuj całe archiwum ZIP (z zachowaniem uprawnień)."
  exit 1
fi
"$PY" -s -E "$DIR/app/acs_panel.py"
status=$?
[ "$status" -ne 0 ] && [ -n "$ACB_IN_TERMINAL" ] && { printf "Naciśnij Enter, aby zamknąć..."; read -r _; }
exit $status
