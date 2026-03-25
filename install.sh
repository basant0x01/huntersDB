#!/bin/bash
set -e
echo "══════════════════════════════════════════════════════════"
echo "  SUBMIND PRO v8.0 — Installer (FastAPI + asyncpg + Redis)"
echo "══════════════════════════════════════════════════════════"

# ── Python ─────────────────────────────────────────────────────────
python3 --version || { echo "Error: python3 not found"; exit 1; }
PYTHON_VER=$(python3 -c 'import sys; print(sys.version_info >= (3, 10))')
if [ "$PYTHON_VER" != "True" ]; then
    echo "Error: Python 3.10+ required"
    exit 1
fi

# ── Virtual environment ────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "▸ Creating virtual environment..."
    python3 -m venv venv
fi

echo "▸ Installing Python packages..."
venv/bin/pip install -q --upgrade pip
venv/bin/pip install -q -r requirements.txt

# ── Check Redis ────────────────────────────────────────────────────
echo ""
echo "▸ Checking services:"
if command -v redis-cli &>/dev/null; then
    redis-cli ping &>/dev/null && echo "  ✓ Redis running" || echo "  ✗ Redis not running (start with: redis-server)"
else
    echo "  ✗ redis-cli not found — install Redis: https://redis.io/download"
fi

# ── Check PostgreSQL ───────────────────────────────────────────────
if command -v psql &>/dev/null; then
    echo "  ✓ psql found"
else
    echo "  ✗ psql not found — install PostgreSQL"
fi

# ── Check scanning tools ───────────────────────────────────────────
echo ""
echo "▸ Scanning tools:"
check_tool() {
    command -v "$1" &>/dev/null && echo "  ✓ $1" \
        || echo "  ✗ $1 NOT found — install: go install -v github.com/projectdiscovery/$2@latest"
}
check_tool httpx     "httpx/cmd/httpx"
check_tool subfinder "subfinder/v2/cmd/subfinder"
check_tool nuclei    "nuclei/v3/cmd/nuclei"

# ── Env file template ──────────────────────────────────────────────
if [ ! -f ".env" ]; then
    echo ""
    echo "▸ Creating .env template..."
    cat > .env <<'EOF'
# SUBMIND PRO v8.0 Environment Configuration
DATABASE_URL=postgresql://submind:submind@localhost:5432/submind
REDIS_URL=redis://localhost:6379/0
SUBMIND_USER=submind
SUBMIND_PASS=submind
SUBMIND_SECRET_KEY=change_me_to_a_random_64_char_hex

# Resource limits
MAX_SUBPROCESSES=4
MAX_CONCURRENT_TASKS=50
MAX_QUEUE_SIZE=10000

# Phase concurrency
PHASE_A_CONCURRENT=20
PHASE_C_CONCURRENT=5
PHASE_D_CONCURRENT=5
EOF
    echo "  ✓ .env created — edit it before starting"
fi

# ── PostgreSQL setup hint ──────────────────────────────────────────
echo ""
echo "▸ PostgreSQL setup (run once):"
echo "  createuser -P submind           # password: submind"
echo "  createdb -O submind submind"
echo "  # Or: psql -U postgres -c \"CREATE USER submind PASSWORD 'submind';\""
echo "  # And: psql -U postgres -c \"CREATE DATABASE submind OWNER submind;\""

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Installation complete!"
echo ""
echo "  1. Edit .env with your configuration"
echo "  2. Set up PostgreSQL (see above)"
echo "  3. Start Redis: redis-server"
echo "  4. Run: ./run.sh"
echo "══════════════════════════════════════════════════════════"
