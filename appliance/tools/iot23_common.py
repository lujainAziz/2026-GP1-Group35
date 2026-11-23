"""Shared safety guards for the IoT-23 offline test tools (IOT23_OFFLINE_TEST.md).

The offline test must never write the device's real database, and its ingest
must never run against the live Suricata log folder (the ingester's reaper
deletes consumed rotated eve files next to the file it reads).
"""
import os
import sys

# Where the appliance services keep their data (systemd units / module defaults).
REAL_DB_PATH = "/home/assas/assas/assas.db"
LIVE_EVE_DIR = "/var/log/suricata"


class UnsafePath(Exception):
    """The given path points at production data."""


def _real(path):
    return os.path.realpath(os.path.abspath(path))


def _same_file(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def check_test_db(path, real_paths=None):
    """Refuse the real database: same path after symlinks, or the same file
    under another name (hard link). Returns the path when it is safe."""
    for real in (REAL_DB_PATH,) if real_paths is None else real_paths:
        if _real(path) == _real(real) or _same_file(path, real):
            raise UnsafePath(
                f"refusing {path}: it is the real Assas database ({real}). "
                "Use a separate test database, e.g. /home/assas/b1test/test.db")
    return path


def check_test_eve(path, live_dirs=None):
    """Refuse an eve.json inside the live Suricata log folder."""
    folder = _real(os.path.dirname(_real(path)))
    for live in (LIVE_EVE_DIR,) if live_dirs is None else live_dirs:
        live_real = _real(live)
        if folder == live_real or folder.startswith(live_real + os.sep):
            raise UnsafePath(
                f"refusing {path}: it is in the live Suricata log folder ({live}). "
                "Run suricata -r with -l <test folder> and ingest that eve.json")
    return path


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    return 2
