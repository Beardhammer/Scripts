#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Zellij loader installer
#
# Usage:
#   bash <(curl -sL https://raw.githubusercontent.com/YOURUSER/YOURREPO/main/install.sh)
#
# What it does:
#   1. Installs the load-zellij script to ~/.local/bin/
#   2. Ensures ~/bin exists (where zellij binary will live)
#   3. Ensures ~/.local/bin and ~/bin are in PATH via shell rc
#   4. Adds the sourcing line to your shell's rc file
# ──────────────────────────────────────────────────────────────

INSTALL_DIR="$HOME/.local/bin"
ZELLIJ_BIN_DIR="$HOME/bin"
SCRIPT_NAME="load-zellij"

info()  { printf '\033[1;34m[info]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[ok]\033[0m    %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn]\033[0m  %s\n' "$*"; }
error() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Embedded load-zellij script ──────────────────────────────
write_load_zellij() {
    cat > "$1" << 'LOAD_ZELLIJ_EOF'
#! /usr/bin/env bash
# Helper function
is_sourced() {
    if [ -n "$ZSH_VERSION" ]; then
        case $ZSH_EVAL_CONTEXT in *:file:*) return 0;; esac
    else  # Add additional POSIX-compatible shell names here, if needed.
        case ${0##*/} in dash|-dash|bash|-bash|ksh|-ksh|sh|-sh) return 0;; esac
    fi
    return 1; # NOT sourced.
}
BASE_0=${BASE_0:-$0}
BASE_SHELL=$(basename "$SHELL")
if is_sourced; then
    zellij-cleanup() {
        [[ -r "$HOME/bin/zellij"    ]] && rm     "$HOME/bin/zellij"
        [[ -d "$HOME/.cache/zellij" ]] && rm -fR "$HOME/.cache/zellij"
        [[ -d /tmp/zellij           ]] && rm -fR /tmp/zellij
        printf 'Zellij has been cleaned up, you can now reinstall it.\n'
    }
    zellij() {
        mkdir -p ~/bin
        if [[ ! -x ~/bin/zellij ]]; then
            if [[ -x $HOME/.cache/chezmoi/tmp/zellij/zellij ]]; then
                ln --symbolic --relative $HOME/.cache/chezmoi/tmp/zellij/zellij ~/bin
            elif [[ ! -x /tmp/zellij/bootstrap/zellij ]]; then
                echo "Grabbing zellij from the web!"
                bash <(curl -sL zellij.dev/launch) "${@}" && return
            fi
        fi
        if [[ -e /tmp/zellij/bootstrap/zellij ]]; then
            mv /tmp/zellij/bootstrap/zellij ~/bin/zellij
            rm -fR /tmp/zellij
        fi
        if [[ -x ~/bin/zellij ]]; then
            ~/bin/zellij "${@}"
        fi
    }
    zellij-completion() {
    if [[ "${BASE_SHELL}" == "zsh" ]]; then
        . <( zellij setup --generate-completion zsh | sed -Ee 's/^(_(zellij) ).*/compdef \1\2/' )
    else
        . <( zellij setup --generate-completion "$BASE_SHELL" )
    fi
    }
    zellij-completion
    if [[ -z "$ZELLIJ_SESSION_NAME" ]]; then
        zellij attach -c $USER@$(hostname)
    fi
elif [[ "$1" == '-' ]]; then
    cat "${BASH_SOURCE[0]}"
else
    SCRIPT_NAME="$BASE_0"
    printf '%s\n' \
        "It seems $SCRIPT_NAME was invoked as a script. It should be sourced instead." \
        'The easiest way is to call it like this:' \
        "    $ . <( $SCRIPT_NAME - ) # Note the '-' after the script's name" \
        ''
fi
LOAD_ZELLIJ_EOF
}

# ── Detect shell and rc file ────────────────────────────────
detect_shell_rc() {
    local shell_name
    shell_name="$(basename "$SHELL")"

    case "$shell_name" in
        zsh)  echo "$HOME/.zshrc"    ;;
        bash)
            if [[ -f "$HOME/.bashrc" ]]; then
                echo "$HOME/.bashrc"
            else
                echo "$HOME/.bash_profile"
            fi
            ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "$HOME/.${shell_name}rc" ;;
    esac
}

SHELL_NAME="$(basename "$SHELL")"
RC_FILE="$(detect_shell_rc)"
SOURCE_LINE='. <( '"$INSTALL_DIR/$SCRIPT_NAME"' - )'

if [[ "$SHELL_NAME" == "fish" ]]; then
    SOURCE_LINE="source ($INSTALL_DIR/$SCRIPT_NAME - | psub)"
fi

# ── Create directories ──────────────────────────────────────
mkdir -p "$INSTALL_DIR"
mkdir -p "$ZELLIJ_BIN_DIR"
ok "Ensured $INSTALL_DIR and $ZELLIJ_BIN_DIR exist"

# ── Write load-zellij ────────────────────────────────────────
info "Installing $SCRIPT_NAME..."
write_load_zellij "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
ok "Installed $INSTALL_DIR/$SCRIPT_NAME"

# ── Ensure PATH includes our directories ─────────────────────
add_to_path_in_rc() {
    local dir="$1"
    local rc="$2"

    if echo "$PATH" | tr ':' '\n' | grep -qxF "$dir"; then
        return
    fi

    if [[ -f "$rc" ]] && grep -qF "$dir" "$rc" 2>/dev/null; then
        return
    fi

    info "Adding $dir to PATH in $rc"
    if [[ "$SHELL_NAME" == "fish" ]]; then
        echo "fish_add_path $dir" >> "$rc"
    else
        echo "export PATH=\"$dir:\$PATH\"" >> "$rc"
    fi
    ok "Added $dir to PATH"
}

add_to_path_in_rc "$INSTALL_DIR"    "$RC_FILE"
add_to_path_in_rc "$ZELLIJ_BIN_DIR" "$RC_FILE"

# ── Add sourcing line to rc file ─────────────────────────────
if [[ -f "$RC_FILE" ]] && grep -qF "$SCRIPT_NAME" "$RC_FILE" 2>/dev/null; then
    warn "Sourcing line already present in $RC_FILE — skipping"
else
    info "Adding sourcing line to $RC_FILE"
    {
        echo ""
        echo "# Zellij loader (added by installer)"
        echo "$SOURCE_LINE"
    } >> "$RC_FILE"
    ok "Added to $RC_FILE"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
ok "Installation complete!"
echo ""
info "Detected shell: $SHELL_NAME"
info "RC file:        $RC_FILE"
echo ""
info "To start using zellij now, run:"
echo ""
echo "    source $RC_FILE"
echo ""
info "Or just open a new terminal session."
echo ""
