"""
workers/adaptive_scanner.py — Adaptive Thread Controller (ATC) Brain v2

Self-regulating httpx scanner that continuously balances:
  • CPU usage  ≤ target (default 70%)
  • Detection speed → maximised within CPU budget

HOW IT WORKS:
  1. Starts httpx with conservative threads
  2. Every BRAIN_TICK seconds samples CPU + output rate
  3. If CPU too high  → reduces threads for NEXT restart
     If CPU too low + rate slow → increases threads for NEXT restart
  4. When adjustment needed → kills current httpx, restarts on REMAINING
     subs with new thread count. "Remaining" is tracked IN MEMORY from
     the on_result_lines callback — never from disk files (avoids races).

KEY FIX vs v1:
  v1 tracked remaining subs by reading the output file after deletion → BUG.
  v2 tracks processed hosts in a set built from on_result_lines callbacks.
  File can be deleted freely without affecting remaining-subs calculation.

DECISION MATRIX:
  CPU > CEIL (82%)        → THROTTLE → threads × 0.70
  CPU > TARGET (70%)      → COOL     → threads × 0.85
  CPU in [45%, 70%]       → HOLD
  CPU < 45% + slow rate   → BOOST    → threads × 1.40
  CPU < 70% + slow rate   → RAMP     → threads × 1.20
  CPU < 70% + good rate   → HOLD     (already optimal)
"""
import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

logger = logging.getLogger("workers.adaptive_scanner")

# ── Brain constants ────────────────────────────────────────────────────────────
CPU_TARGET   = 70.0
CPU_CEIL     = 82.0
CPU_FLOOR    = 45.0

BRAIN_TICK   = 5.0     # seconds between decisions (increased from 3 to reduce churn)
EWMA_CPU_A   = 0.35
EWMA_RATE_A  = 0.25

MIN_THREADS  = 10
MAX_THREADS  = 250
MIN_RATE_LIM = 50
MAX_RATE_LIM = 600

MIN_TARGET_RATE     = 3.0   # subs/sec minimum before we try to speed up
MIN_ADJUST_INTERVAL = 12.0  # seconds between adjustments (prevents oscillation)


def _cpu_now() -> float:
    """Instant non-blocking CPU sample."""
    if _PSUTIL:
        return psutil.cpu_percent(interval=None)
    try:
        load1, _, _ = os.getloadavg()
        cores = os.cpu_count() or 1
        return min(100.0, (load1 / cores) * 100.0)
    except Exception:
        return 0.0


# ONLY AdaptiveBrain changed — everything else SAME

class AdaptiveBrain:
    def __init__(self, initial_threads: int, initial_rate: int,
                 cpu_target: float = CPU_TARGET):

        self.threads    = int(initial_threads)
        self.rate_lim   = int(initial_rate)
        self.base_target = cpu_target

        self._cpu_ewma  = 0.0
        self._rate_ewma = 0.0

        self._prev_cpu   = 0.0
        self._prev_rate  = 0.0
        self._prev_eff   = 0.0

        self._peak_rate  = 0.0
        self._plateau_counter = 0

        self._last_adjust_ts = 0.0
        self._last_lines     = 0
        self._last_tick_ts   = time.monotonic()

        self._adjustments = 0
        self._initialized = False

    def tick(self, output_lines: int) -> Tuple[bool, str]:

        now     = time.monotonic()
        elapsed = max(0.1, now - self._last_tick_ts)
        self._last_tick_ts = now

        # ── CPU ─────────────────────────────
        raw_cpu = _cpu_now()
        if not self._initialized:
            self._cpu_ewma = raw_cpu
            self._initialized = True
        else:
            self._cpu_ewma = EWMA_CPU_A * raw_cpu + (1 - EWMA_CPU_A) * self._cpu_ewma

        # ── RATE ────────────────────────────
        new_lines = max(0, output_lines - self._last_lines)
        self._last_lines = output_lines

        raw_rate = new_lines / elapsed
        self._rate_ewma = EWMA_RATE_A * raw_rate + (1 - EWMA_RATE_A) * self._rate_ewma

        cpu  = self._cpu_ewma
        rate = self._rate_ewma
        t    = self.threads
        rl   = self.rate_lim

        # Track best speed seen
        if rate > self._peak_rate:
            self._peak_rate = rate

        rate_trend = rate - self._prev_rate
        cpu_slope  = cpu - self._prev_cpu

        self._prev_cpu  = cpu
        self._prev_rate = rate

        can_adjust = (now - self._last_adjust_ts) >= MIN_ADJUST_INTERVAL

        # ── EMERGENCY ───────────────────────
        if cpu > CPU_CEIL:
            new_t  = max(MIN_THREADS, int(t * 0.70))
            new_rl = max(MIN_RATE_LIM, int(rl * 0.70))
            return self._apply(new_t, new_rl, f"EMERGENCY cpu={cpu:.1f}%")

        if not can_adjust:
            return False, f"HOLD cooldown cpu={cpu:.1f}% rate={rate:.2f}"

        # ── DYNAMIC TARGET ──────────────────
        if abs(cpu_slope) < 2:
            cpu_target = min(75, self.base_target + 3)
        else:
            cpu_target = max(65, self.base_target - 5)

        error = cpu - cpu_target

        # ── SCALE DOWN (protect CPU)
        if error > 0 or cpu_slope > 5:

            adjust = 0.12 + (cpu_slope * 0.02)
            adjust = min(0.40, max(0.08, adjust))

            self._plateau_counter = 0

            new_t  = max(MIN_THREADS, int(t * (1 - adjust)))
            new_rl = max(MIN_RATE_LIM, int(rl * (1 - adjust)))

            return self._apply(new_t, new_rl,
                f"DOWN cpu={cpu:.1f}% slope={cpu_slope:.2f}")

        # ── SCALE UP (AGGRESSIVE SPEED SEARCH)
        if error < -5:

            # detect plateau
            if rate < self._peak_rate * 0.95:
                self._plateau_counter += 1
            else:
                self._plateau_counter = 0

            # if plateau confirmed → stop scaling
            if self._plateau_counter >= 3:
                return False, f"HOLD plateau rate={rate:.2f}"

            # aggressive ramp-up
            adjust = 0.12

            if rate_trend > 0:
                adjust *= 1.4   # push harder if improving

            new_t = min(MAX_THREADS, int(t * (1 + adjust)))

            # soft prediction (less strict)
            cpu_per_thread = cpu / max(t, 1)
            predicted_cpu = cpu_per_thread * new_t

            if predicted_cpu > cpu_target + 10:
                return False, "HOLD predicted overload"

            new_rl = min(MAX_RATE_LIM, int(rl * (new_t / max(t, 1))))

            return self._apply(new_t, new_rl,
                f"EXPLORE cpu={cpu:.1f}% rate={rate:.2f}")

        # ── STABLE ZONE
        if abs(error) <= 5:
            return False, f"HOLD stable cpu={cpu:.1f}% rate={rate:.2f}"

        return False, f"HOLD cpu={cpu:.1f}% rate={rate:.2f}"

    def _apply(self, new_t, new_rl, reason):

        if new_t == self.threads:
            return False, "HOLD-UNCHANGED"

        change = abs(new_t - self.threads) / max(self.threads, 1)

        if change < 0.12:
            return False, f"HOLD small-change {change:.2f}"

        self.threads         = new_t
        self.rate_lim        = new_rl
        self._last_adjust_ts = time.monotonic()
        self._adjustments   += 1

        return True, f"{reason} → t={new_t} rl={new_rl}"

    def stats(self) -> Dict:
        return {
            "threads": self.threads,
            "rate_lim": self.rate_lim,
            "cpu": round(self._cpu_ewma, 1),
            "rate": round(self._rate_ewma, 2),
            "adjustments": self._adjustments,
        }


async def _read_new_lines(path: Path, offset: int) -> Tuple[List[str], int]:
    """Read new lines from output file since last offset. Never throws."""
    if not path.exists():
        return [], offset
    try:
        def _r():
            with open(path, "r", errors="ignore") as fh:
                fh.seek(offset)
                data = fh.read()
                return data, fh.tell()
        data, new_off = await asyncio.to_thread(_r)
        return [l for l in data.splitlines() if l.strip()], new_off
    except Exception:
        return [], offset


def _extract_host_from_line(line: str) -> Optional[str]:
    """Extract hostname from httpx JSON output line."""
    try:
        d = json.loads(line)
        h = (d.get("input", "") or "")
        h = h.replace("http://", "").replace("https://", "")
        h = h.split("/")[0].split(":")[0].lower().strip()
        return h if h else None
    except Exception:
        return None


async def run_httpx_adaptive(
    pool,
    subdomains: List[str],
    project_id: str,
    project_name: str,
    output_dir: Path,
    initial_threads: int,
    initial_rate: int,
    timeout_secs: int,
    extra_flags: List[str],
    job_id: Optional[str],
    batch_num: int = 1,
    batch_total: int = 1,
    total_all: int = 0,
    found_so_far: int = 0,
    on_result_lines: Optional[Callable] = None,
    cpu_target: float = CPU_TARGET,
    manager_ref=None,
) -> Tuple[int, Dict]:
    """
    Run httpx with ATC brain. Returns (total_output_lines, brain_stats).

    Restart safety: processed hosts tracked IN MEMORY via on_result_lines.
    Never reads from deleted output files. No infinite loops.
    """
    from process_manager.manager import manager as _manager
    from utils.log import log as _log
    mgr = manager_ref or _manager

    # Prime psutil
    if _PSUTIL:
        psutil.cpu_percent(interval=None)
        await asyncio.sleep(0.1)
        psutil.cpu_percent(interval=None)

    brain = AdaptiveBrain(initial_threads, initial_rate, cpu_target)

    # KEY FIX: track processed hosts IN MEMORY, not from disk
    # Built from on_result_lines callback — survives file deletion
    processed_hosts: Set[str] = set()
    remaining = list(subdomains)
    total_output_lines = 0
    run_idx = 0
    uid_base = uuid.uuid4().hex

    await _log(pool,
        f"  [ATC] Init: {len(remaining)} subs "
        f"t={brain.threads} rl={brain.rate_lim} "
        f"cpu_target={cpu_target:.0f}% batch={batch_num}/{batch_total}",
        "info", "httpx", job_id)

    while remaining:
        run_idx += 1
        uid = f"{uid_base}_{run_idx}"
        ti  = output_dir / f"hx_in_{uid}.txt"
        to  = output_dir / f"hx_out_{uid}.json"

        if run_idx > 1:
            await _log(pool,
                f"  [ATC] Restart #{run_idx}: "
                f"{len(remaining)} remaining subs "
                f"t={brain.threads} rl={brain.rate_lim}",
                "info", "httpx", job_id)

        try:
            # Write input file
            await asyncio.to_thread(ti.write_text, "\n".join(remaining))

            cmd = [
                "httpx",
                "-l", str(ti),
                "-o", str(to),
                "-json", "-silent", "-no-color",
                "-threads",    str(brain.threads),
                "-rate-limit", str(brain.rate_lim),
                *extra_flags,
            ]

            proc = await mgr.run_streaming(
                f"httpx_atc_{batch_num}_{run_idx}", cmd, timeout_secs)

            read_offset     = 0
            output_lines    = 0  # lines seen in THIS run's output file
            last_tick_ts    = time.monotonic()
            should_restart  = False  # set True by brain to trigger restart

            try:
                while proc.returncode is None:
                    await asyncio.sleep(1.0)

                    # ── Read new output ────────────────────────────────────
                    new_lines, read_offset = await _read_new_lines(to, read_offset)
                    if new_lines:
                        output_lines       += len(new_lines)
                        total_output_lines += len(new_lines)

                        # Track processed hosts IN MEMORY
                        for line in new_lines:
                            h = _extract_host_from_line(line)
                            if h:
                                processed_hosts.add(h)

                        if on_result_lines:
                            await on_result_lines(new_lines)

                    # ── Brain tick ────────────────────────────────────────
                    now_ts = time.monotonic()
                    if (now_ts - last_tick_ts) >= BRAIN_TICK:
                        last_tick_ts = now_ts
                        changed, decision = brain.tick(output_lines)

                        await _log(pool,
                            f"  [ATC] {decision} | "
                            f"processed={len(processed_hosts)}/{len(subdomains)} "
                            f"adj={brain._adjustments}",
                            "info", "httpx", job_id)

                        if changed:
                            should_restart = True
                            # Compute remaining BEFORE killing proc
                            # Uses in-memory set — no file reads needed
                            new_remaining = [
                                s for s in remaining
                                if s.lower() not in processed_hosts
                            ]
                            await _log(pool,
                                f"  [ATC] Killing httpx: "
                                f"{len(processed_hosts)} done, "
                                f"{len(new_remaining)} remaining",
                                "info", "httpx", job_id)
                            remaining = new_remaining
                            # Kill the process — will exit the while loop
                            if proc.returncode is None:
                                try:
                                    proc.terminate()
                                except Exception:
                                    pass
                            break

                # Wait briefly for proc to fully stop before final flush
                # This prevents race condition where proc still writes while we read
                if should_restart and proc.returncode is None:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        pass  # will be killed in release_process

                # Final flush after proc exits
                final_lines, _ = await _read_new_lines(to, read_offset)
                if final_lines:
                    output_lines       += len(final_lines)
                    total_output_lines += len(final_lines)
                    for line in final_lines:
                        h = _extract_host_from_line(line)
                        if h:
                            processed_hosts.add(h)
                    if on_result_lines:
                        await on_result_lines(final_lines)

            finally:
                # Always release the process slot
                await mgr.release_process(proc)

            # After proc released: determine if we continue
            if not should_restart:
                # Normal completion — all subs processed
                remaining = []
                break

            # should_restart=True — continue outer while with updated remaining
            if not remaining:
                break

        finally:
            # Safe to delete files here — remaining already computed in memory
            for f_path in (ti, to):
                try:
                    await asyncio.to_thread(f_path.unlink, missing_ok=True)
                except Exception:
                    pass

    stats = brain.stats()
    await _log(pool,
        f"  [ATC] Done: {total_output_lines} results | "
        f"adj={stats['adjustments']} "
        f"final t={stats['threads']} cpu={stats['cpu']:.1f}%",
        "success", "httpx", job_id)

    return total_output_lines, stats
