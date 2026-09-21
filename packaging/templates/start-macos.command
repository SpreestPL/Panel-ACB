#!/bin/bash
# Spreest - Panel ACB (kontrola dostępu) - start na macOS (dwuklik)
{{MODE_ENV}}DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
# Pliki pobrane z internetu mają atrybut kwarantanny - bez jego zdjęcia macOS
# blokuje dołączonego Pythona. Dotyczy wyłącznie tego folderu.
xattr -dr com.apple.quarantine "$DIR" 2>/dev/null
case "$(uname -m)" in
  arm64) PY="$DIR/runtime/macos-arm64/bin/python3" ;;
  *)     PY="$DIR/runtime/macos-x64/bin/python3" ;;
esac
if [ ! -x "$PY" ]; then
  echo "Nie znaleziono $PY"
  echo "Rozpakuj całe archiwum ZIP i uruchom ten plik z rozpakowanego folderu."
  read -r -p "Naciśnij Enter, aby zamknąć..."
  exit 1
fi
"$PY" -s -E "$DIR/app/acs_panel.py"
