"""
Side-effecting helper: importing this module prepends a wall-clock timestamp
to every `print()` call (in the importing process), so timing across
deploy / post-deploy phases is easy to read in `tee`'d log files.

Usage:
    import log_setup  # noqa: F401  -- imported for side effect

Place near the top of an entry-point script. Because Python looks up
`print` via `builtins` at call time, role_*.py modules imported later
also get the patched version without any code change in them.
"""
import builtins
import datetime

_orig_print = builtins.print


def _ts_print(*args, **kwargs):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _orig_print(f"[{ts}]", *args, **kwargs)


builtins.print = _ts_print
