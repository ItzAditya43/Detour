#!/usr/bin/env bash
# Build Detour and install it for the current user: binaries in ~/.local/bin,
# icon in ~/.local/share/icons, launcher entry in ~/.local/share/applications.
# No root needed. Uninstall with: packaging/install-user.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="$HOME/.local/bin"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$BIN/detour" "$BIN/dns-helper" "$APPS/detour.desktop"
  rm -f "$ICONS"/{32x32,128x128,512x512}/apps/detour.png
  update-desktop-database "$APPS" 2>/dev/null || true
  echo "Detour removed. Your config in ~/.config/detour was left in place."
  exit 0
fi

cargo build --release -p dns-helper
cargo build --release -p detour --features custom-protocol

install -Dm755 target/release/detour     "$BIN/detour"
install -Dm755 target/release/dns-helper "$BIN/dns-helper"
install -Dm644 src-tauri/icons/32x32.png   "$ICONS/32x32/apps/detour.png"
install -Dm644 src-tauri/icons/128x128.png "$ICONS/128x128/apps/detour.png"
install -Dm644 src-tauri/icons/icon.png    "$ICONS/512x512/apps/detour.png"

cat > "$APPS/detour.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Detour
GenericName=DNS & App Tunnel
Comment=Encrypted DNS for the whole system, and a tunnel for the apps you choose
Exec=$BIN/detour
Icon=detour
Terminal=false
Categories=Network;
Keywords=dns;doh;vpn;tunnel;wireguard;warp;youtube;
StartupWMClass=detour
DESKTOP

update-desktop-database "$APPS" 2>/dev/null || true
gtk-update-icon-cache -f -t "$ICONS" 2>/dev/null || true
echo "Detour installed. Find it in your app launcher."
