#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SUBMIND PRO v8.0 — Production Startup Script (FIXED)
# ══════════════════════════════════════════════════════════════════

set -e

cd "$(dirname "$0")"

# ── CRITICAL FIX: avoid stdlib shadowing ───────────────────────────
unset PYTHONPATH

# ── Auto-fix bad folder name (queue → task_queue) ─────────────────
if [ -d "queue" ] && [ ! -d "task_queue" ]; then
  echo "⚠ Fixing dangerous folder name: queue → task_queue"
  mv queue task_queue

  echo "⚠ Updating imports..."
  grep -rl "queue\." . | xargs sed -i 's/queue\./task_queue\./g' || true
  grep -rl "from task_queue" . | xargs sed -i 's/from task_queue/from task_queue/g' || true

  echo "✓ Auto-fix complete"
fi

# ── Load environment ───────────────────────────────────────────────
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
fi

# ── Defaults ──────────────────────────────────────────────────────
DATABASE_URL=${DATABASE_URL:-postgresql://submind:submind@127.0.0.1:5432/submind}
REDIS_URL=${REDIS_URL:-redis://localhost:6379/0}
PYTHON="venv/bin/python"

# ── Pretty print ──────────────────────────────────────────────────
echo "══════════════════════════════════════════"
echo "  HuntersDB v1.0 — Startup"
echo "══════════════════════════════════════════"

# ── Check venv ────────────────────────────────────────────────────
if [ ! -f "$PYTHON" ]; then
  echo "❌ Virtualenv not found. Run: python3 -m venv venv && venv/bin/pip install -r requirements.txt"
  exit 1
fi

# ── Check Redis ───────────────────────────────────────────────────
echo "▸ Checking Redis..."
if redis-cli ping &>/dev/null; then
  echo "  ✓ Redis running"
else
  echo "  ✗ Redis not running (start with: redis-server)"
  exit 1
fi

# ── Check PostgreSQL ──────────────────────────────────────────────
echo "▸ Checking PostgreSQL..."
if $PYTHON - <<EOF
import asyncio, asyncpg
async def test():
    conn = await asyncpg.connect("$DATABASE_URL")
    await conn.close()
asyncio.run(test())
EOF
then
  echo "  ✓ PostgreSQL reachable"
else
  echo "  ✗ PostgreSQL connection failed"
  echo "    → DATABASE_URL=$DATABASE_URL"
  exit 1
fi

# ── Check Python deps ─────────────────────────────────────────────
echo "▸ Checking Python packages..."
if $PYTHON -c "import fastapi, asyncpg, redis, aiohttp" &>/dev/null; then
  echo "  ✓ All packages installed"
else
  echo "  ✗ Missing packages → run: venv/bin/pip install -r requirements.txt"
  exit 1
fi

# ── Check tools ───────────────────────────────────────────────────
echo "▸ Checking scanning tools..."
check_tool() {
  command -v "$1" &>/dev/null && echo "  ✓ $1" || echo "  ⚠ $1 not found"
}
check_tool httpx
check_tool subfinder
check_tool nuclei

# ── Start services ────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  Starting HuntersDB PRO..."
echo "══════════════════════════════════════════"

# Start worker
$PYTHON -m workers.queue_consumer &
WORKER_PID=$!
echo "▸ Worker started (PID: $WORKER_PID)"

# Cleanup handler
cleanup() {
  echo ""
  echo "▸ Shutting down..."
  kill $WORKER_PID 2>/dev/null || true
  wait $WORKER_PID 2>/dev/null || true
  echo "  Done"
}
trap cleanup EXIT INT TERM

# Start API

echo "▸ Starting API server..."
$PYTHON main.py
