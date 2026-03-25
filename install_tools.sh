#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  SUBMIND PRO — Recon Intelligence Tool Installer
#  Installs all external tools required by the recon pipeline.
#  Run: bash install_tools.sh
# ═══════════════════════════════════════════════════════════════════
set -e

GO_BIN="$HOME/go/bin"
export PATH="$PATH:$GO_BIN"

ok()   { echo "  ✓  $*"; }
warn() { echo "  ⚠  $*"; }
err()  { echo "  ✗  $*"; }
hdr()  { echo; echo "── $* ──────────────────────────────────────────"; }

check_cmd() { command -v "$1" &>/dev/null; }

# ── Prerequisites ────────────────────────────────────────────────────
hdr "Prerequisites"
check_cmd go   && ok "Go $(go version | awk '{print $3}')" || { err "Go not found — install from https://go.dev/dl"; exit 1; }
check_cmd pip3 && ok "pip3 found" || { err "pip3 not found"; exit 1; }
check_cmd npm  && ok "npm $(npm --version)" || warn "npm not found — retire.js won't be installed"

# ── Go tools ─────────────────────────────────────────────────────────
hdr "Go-based tools (projectdiscovery)"

install_go_tool() {
    local name=$1 pkg=$2
    if check_cmd "$name"; then
        ok "$name already installed"
    else
        echo "  → Installing $name..."
        go install "$pkg" && ok "$name installed" || warn "$name install failed"
    fi
}

install_go_tool naabu     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool subzy     "github.com/PentestPad/subzy@latest"
install_go_tool gau       "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
install_go_tool hakrawler "github.com/hakluke/hakrawler@latest"
install_go_tool ffuf      "github.com/ffuf/ffuf/v2@latest"

# ── Python tools ──────────────────────────────────────────────────────
hdr "Python tools"

# LinkFinder
if check_cmd linkfinder || python3 -c "import linkfinder" 2>/dev/null; then
    ok "linkfinder already installed"
else
    echo "  → Installing LinkFinder..."
    TOOLS_DIR="$HOME/tools"
    mkdir -p "$TOOLS_DIR"
    if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
        git clone --quiet https://github.com/GerbenJavado/LinkFinder.git "$TOOLS_DIR/LinkFinder" 2>/dev/null \
            && ok "LinkFinder cloned" || warn "LinkFinder clone failed"
    fi
    if [ -f "$TOOLS_DIR/LinkFinder/setup.py" ]; then
        pip3 install -q -r "$TOOLS_DIR/LinkFinder/requirements.txt" 2>/dev/null \
            && ok "LinkFinder dependencies installed" || warn "LinkFinder deps failed"
        # Make executable
        ln -sf "$TOOLS_DIR/LinkFinder/linkfinder.py" /usr/local/bin/linkfinder 2>/dev/null || true
    fi
fi

# TruffleHog v3
if check_cmd trufflehog; then
    ok "trufflehog $(trufflehog --version 2>&1 | head -1)"
else
    echo "  → Installing TruffleHog v3..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null \
        && ok "trufflehog installed" || warn "trufflehog install failed — try: pip3 install trufflehog"
fi

# s3scanner
if check_cmd s3scanner; then
    ok "s3scanner already installed"
else
    echo "  → Installing s3scanner..."
    pip3 install -q s3scanner 2>/dev/null \
        && ok "s3scanner installed" || warn "s3scanner install failed"
fi

# ── Node tools ────────────────────────────────────────────────────────
hdr "Node.js tools"

if check_cmd npm; then
    if check_cmd retire; then
        ok "retire.js already installed"
    else
        echo "  → Installing retire.js..."
        npm install -g retire 2>/dev/null \
            && ok "retire.js installed" || warn "retire.js install failed"
    fi
else
    warn "npm not available — retire.js skipped"
fi

# ── Update nuclei templates ───────────────────────────────────────────
hdr "Nuclei templates"
if check_cmd nuclei; then
    echo "  → Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "Templates updated" || warn "Template update failed"
else
    warn "nuclei not installed"
fi

# ── Summary ───────────────────────────────────────────────────────────
hdr "Tool check"
TOOLS=(naabu katana hakrawler ffuf subzy gau waybackurls trufflehog s3scanner nuclei)
for t in "${TOOLS[@]}"; do
    check_cmd "$t" && ok "$t" || warn "$t — NOT FOUND (some features will be skipped)"
done
check_cmd retire && ok "retire (retire.js)" || warn "retire — NOT FOUND"
[ -f "$HOME/tools/LinkFinder/linkfinder.py" ] && ok "linkfinder" || warn "linkfinder — NOT FOUND"

echo
echo "═══════════════════════════════════════════════════════════"
echo "  Tool installation complete. Start SUBMIND PRO: ./run.sh"
echo "═══════════════════════════════════════════════════════════"
