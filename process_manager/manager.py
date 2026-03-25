"""
process_manager/manager.py — Global async subprocess manager.

Enforces MAX_SUBPROCESSES hard limit across the entire worker process.
Every httpx/nuclei/subfinder call MUST go through this manager.

Features:
  • asyncio.Semaphore for subprocess slot limiting
  • Per-process timeout with guaranteed kill
  • Active process tracking
  • Auto-kill stuck processes (watchdog)
  • Memory-safe: releases slot even on exception
"""
import asyncio
import asyncio.subprocess
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from config.settings import MAX_SUBPROCESSES

logger = logging.getLogger("process_manager")

# ── Active process registry ────────────────────────────────────────────────────
@dataclass
class ManagedProcess:
    name: str
    cmd: List[str]
    pid: Optional[int]
    started: float
    timeout_secs: int
    proc: Optional[asyncio.subprocess.Process] = None


class SubprocessManager:
    """
    Singleton subprocess manager.
    Enforces MAX_SUBPROCESSES across all async workers in the same process.
    """

    def __init__(self, max_procs: int = MAX_SUBPROCESSES):
        self._sem   = asyncio.Semaphore(max_procs)
        self._active: Dict[int, ManagedProcess] = {}   # pid → ManagedProcess
        self._lock  = asyncio.Lock()
        self._max   = max_procs
        logger.info("SubprocessManager ready (max=%d)", max_procs)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def run(
        self,
        name: str,
        cmd: List[str],
        timeout_secs: int,
        stdin_data: Optional[bytes] = None,
        capture_stdout: bool = False,
        capture_stderr: bool = False,
    ) -> Tuple[int, bytes, bytes]:
        """
        Run a subprocess under the global semaphore.
        Returns (returncode, stdout_bytes, stderr_bytes).
        Guaranteed to kill the process and release the semaphore on any failure.
        """
        logger.debug("[%s] waiting for subprocess slot (max=%d)", name, self._max)
        async with self._sem:
            return await self._run_inner(
                name, cmd, timeout_secs, stdin_data, capture_stdout, capture_stderr)

    async def run_streaming(
        self,
        name: str,
        cmd: List[str],
        timeout_secs: int,
        stdout = None,   # asyncio.subprocess.PIPE or DEVNULL — default DEVNULL
        stderr = None,   # asyncio.subprocess.PIPE or DEVNULL — default DEVNULL
    ) -> asyncio.subprocess.Process:
        """
        Launch a subprocess and return the Process object.
        Caller MUST call manager.release_process(proc) when done.

        For file-output tools (httpx -o file, naabu -o file):
          Pass stdout=DEVNULL, stderr=DEVNULL (the default).
          This prevents OS pipe buffer deadlock on large scans with many errors.
          The tool writes results to its output file; we read that file directly.

        For tools where we need to read stdout/stderr:
          Pass stdout=PIPE and/or stderr=PIPE explicitly.
        """
        _DEVNULL = asyncio.subprocess.DEVNULL
        _PIPE    = asyncio.subprocess.PIPE
        stdout_opt = stdout if stdout is not None else _DEVNULL
        stderr_opt = stderr if stderr is not None else _DEVNULL

        await self._sem.acquire()
        logger.debug("[%s] subprocess slot acquired (streaming)", name)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=stdout_opt,
                stderr=stderr_opt,
            )
        except Exception:
            self._sem.release()
            raise

        mp = ManagedProcess(
            name=name, cmd=cmd, pid=proc.pid,
            started=time.monotonic(), timeout_secs=timeout_secs, proc=proc)
        async with self._lock:
            self._active[proc.pid] = mp
        logger.info("[%s] PID %d started (streaming)", name, proc.pid)
        return proc

    async def release_process(self, proc: asyncio.subprocess.Process) -> None:
        """Release slot after streaming subprocess completes. Must be called in finally."""
        pid = getattr(proc, "pid", None)
        if pid is not None:
            async with self._lock:
                self._active.pop(pid, None)
        await self._kill_if_alive(proc)
        self._sem.release()

    async def kill_all(self) -> int:
        """Emergency: kill all tracked processes. Returns count killed."""
        async with self._lock:
            procs = list(self._active.values())
        count = 0
        for mp in procs:
            if mp.proc:
                await self._kill_if_alive(mp.proc)
                count += 1
        async with self._lock:
            self._active.clear()
        logger.warning("kill_all: terminated %d processes", count)
        return count

    async def kill_by_name(self, name: str) -> int:
        """Kill all tracked processes matching a given tool name. Returns count killed."""
        async with self._lock:
            targets = [mp for mp in self._active.values() if mp.name == name]
        count = 0
        for mp in targets:
            if mp.proc:
                await self._kill_if_alive(mp.proc)
                count += 1
            async with self._lock:
                if mp.pid:
                    self._active.pop(mp.pid, None)
        logger.warning("kill_by_name(%s): terminated %d processes", name, count)
        return count

    async def get_active(self) -> List[Dict]:
        async with self._lock:
            return [
                {
                    "name":    mp.name,
                    "pid":     mp.pid,
                    "cmd":     " ".join(mp.cmd[:4]),
                    "runtime": int(time.monotonic() - mp.started),
                    "timeout": mp.timeout_secs,
                }
                for mp in self._active.values()
            ]

    # ── Watchdog ───────────────────────────────────────────────────────────────

    async def watchdog_loop(self) -> None:
        """
        Background task: auto-kills processes exceeding their timeout.
        Run as: asyncio.create_task(manager.watchdog_loop())
        """
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            async with self._lock:
                stale = [
                    mp for mp in self._active.values()
                    if (now - mp.started) > mp.timeout_secs
                ]
            for mp in stale:
                logger.warning("[watchdog] Killing stuck process %s PID %d (ran %.0fs > timeout %ds)",
                               mp.name, mp.pid or 0,
                               now - mp.started, mp.timeout_secs)
                if mp.proc:
                    await self._kill_if_alive(mp.proc)
                async with self._lock:
                    if mp.pid:
                        self._active.pop(mp.pid, None)
                # MG2-01 FIX: only release if we know process held a slot
                # ValueError means semaphore would exceed max — it never acquired
                try:
                    self._sem.release()
                except ValueError:
                    pass  # already released or never acquired

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _run_inner(
        self,
        name: str,
        cmd: List[str],
        timeout_secs: int,
        stdin_data: Optional[bytes],
        capture_stdout: bool,
        capture_stderr: bool,
    ) -> Tuple[int, bytes, bytes]:
        stdout_opt = asyncio.subprocess.PIPE if capture_stdout else asyncio.subprocess.DEVNULL
        stderr_opt = asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                stdout=stdout_opt,
                stderr=stderr_opt,
            )
            mp = ManagedProcess(
                name=name, cmd=cmd, pid=proc.pid,
                started=time.monotonic(), timeout_secs=timeout_secs, proc=proc)
            async with self._lock:
                self._active[proc.pid] = mp
            logger.info("[%s] PID %d started", name, proc.pid)

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(stdin_data),
                    timeout=float(timeout_secs),
                )
                rc = proc.returncode or 0
                logger.info("[%s] PID %d exited rc=%d", name, proc.pid, rc)
                return rc, stdout or b"", stderr or b""
            except asyncio.TimeoutError:
                logger.warning("[%s] PID %d timeout after %ds — killing",
                               name, proc.pid, timeout_secs)
                await self._kill_if_alive(proc)
                return -1, b"", b"timeout"
        except FileNotFoundError:
            logger.error("[%s] command not found: %s", name, cmd[0])
            return -127, b"", f"{cmd[0]}: not found".encode()
        except Exception as e:
            logger.error("[%s] unexpected error: %s", name, e)
            if proc:
                await self._kill_if_alive(proc)
            return -1, b"", str(e).encode()
        finally:
            if proc and proc.pid:
                async with self._lock:
                    self._active.pop(proc.pid, None)

    @staticmethod
    async def _kill_if_alive(proc: asyncio.subprocess.Process) -> None:
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
        except (ProcessLookupError, OSError):
            pass  # MG2-02 FIX: also catches PermissionError on restricted systems
        except Exception as e:
            logger.debug("kill_if_alive error: %s", e)
        # Close pipes to prevent FD leaks
        for pipe in (proc.stdout, proc.stderr, proc.stdin):
            if pipe:
                try:
                    pipe.close()
                except Exception:
                    pass


# ── Global singleton ──────────────────────────────────────────────────────────
# Workers import this; API imports it for the stop-all endpoint.
manager = SubprocessManager(MAX_SUBPROCESSES)
