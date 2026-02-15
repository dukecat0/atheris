"""Fuzz target: a structured log / event processor.

This is a realistic target that mimics how applications parse structured
log lines and event streams.  Crucially, it uses string operations that
Atheris's existing _trace_cmp (COMPARE_OP hook) does NOT cover:

  - ``"needle" in haystack``  (CONTAINS_OP, not COMPARE_OP)
  - ``str.find()`` / ``str.index()``
  - ``str.split(delimiter)``
  - ``str.count()``
  - ``str.replace()``
  - dictionary key lookups (``d[key]``, ``key in d``)

These are all common real-world patterns.  The string literals used in
these operations are invisible to the baseline fuzzer but become available
as dictionary entries when literal-emission is active — giving the
modified build a clear advantage.
"""

from __future__ import annotations

import os
import sys

try:
  import atheris
except ImportError:  # pragma: no cover
  import importlib.util
  import pathlib

  repo_root = pathlib.Path(__file__).resolve().parent
  atheris_init = repo_root / "src" / "__init__.py"
  spec = importlib.util.spec_from_file_location("atheris", atheris_init)
  if spec is None or spec.loader is None:
    raise
  atheris = importlib.util.module_from_spec(spec)
  sys.modules["atheris"] = atheris
  spec.loader.exec_module(atheris)


# ---------------------------------------------------------------------------
# Event severity levels — used via dictionary key lookup, NOT comparison.
# ---------------------------------------------------------------------------
_SEVERITY_WEIGHTS: dict[str, int] = {
    "TRACE": 0,
    "DEBUG": 1,
    "INFO": 2,
    "WARN": 3,
    "ERROR": 4,
    "FATAL": 5,
}

# ---------------------------------------------------------------------------
# Known subsystem tags — checked via ``tag in _KNOWN_SUBSYSTEMS`` which
# compiles to CONTAINS_OP on the set, not COMPARE_OP.
# ---------------------------------------------------------------------------
_KNOWN_SUBSYSTEMS: set[str] = {
    "auth",
    "database",
    "cache",
    "gateway",
    "scheduler",
    "worker",
    "billing",
    "notification",
}

# ---------------------------------------------------------------------------
# Action dispatch table — looked up with ``_ACTION_HANDLERS[action]``.
# ---------------------------------------------------------------------------

# Counters that make branches observable to coverage instrumentation.
_stats: dict[str, int] = {}


def _handle_login(fields: dict[str, str]) -> None:
  user = fields.get("user", "")
  # ``"admin" in user`` uses CONTAINS_OP
  if "admin" in user:
    _stats["admin_login"] = _stats.get("admin_login", 0) + 1
  if "root" in user:
    _stats["root_login"] = _stats.get("root_login", 0) + 1
  method = fields.get("method", "")
  if "oauth" in method:
    _stats["oauth"] = _stats.get("oauth", 0) + 1
  elif "certificate" in method:
    _stats["cert"] = _stats.get("cert", 0) + 1


def _handle_query(fields: dict[str, str]) -> None:
  sql = fields.get("sql", "")
  # All of these are CONTAINS_OP — not hooked by _trace_cmp
  if "SELECT" in sql:
    _stats["select"] = _stats.get("select", 0) + 1
  if "INSERT" in sql:
    _stats["insert"] = _stats.get("insert", 0) + 1
  if "UPDATE" in sql:
    _stats["update"] = _stats.get("update", 0) + 1
  if "DELETE" in sql:
    _stats["delete"] = _stats.get("delete", 0) + 1
  if "DROP" in sql:
    _stats["drop"] = _stats.get("drop", 0) + 1
    # ``sql.count()`` — not hooked
    if sql.count("DROP") > 1 and "CASCADE" in sql:
      _stats["dangerous_drop"] = _stats.get("dangerous_drop", 0) + 1


def _handle_request(fields: dict[str, str]) -> None:
  path = fields.get("path", "")
  # ``str.find()`` — not hooked by _trace_cmp
  api_pos = path.find("/api/v2/")
  if api_pos >= 0:
    _stats["api_v2"] = _stats.get("api_v2", 0) + 1
    # deeper: what comes after /api/v2/?
    rest = path[api_pos + 8:]
    # ``str.find()`` again
    if rest.find("users") >= 0:
      _stats["api_v2_users"] = _stats.get("api_v2_users", 0) + 1
    if rest.find("billing") >= 0:
      _stats["api_v2_billing"] = _stats.get("api_v2_billing", 0) + 1
    if rest.find("admin") >= 0:
      _stats["api_v2_admin"] = _stats.get("api_v2_admin", 0) + 1

  internal_pos = path.find("/internal/")
  if internal_pos >= 0:
    _stats["internal"] = _stats.get("internal", 0) + 1
    after = path[internal_pos + 10:]
    if after.find("healthz") >= 0:
      _stats["healthz"] = _stats.get("healthz", 0) + 1
    if after.find("metrics") >= 0:
      _stats["metrics"] = _stats.get("metrics", 0) + 1
    if after.find("debug") >= 0:
      _stats["debug_endpoint"] = _stats.get("debug_endpoint", 0) + 1


def _handle_cache(fields: dict[str, str]) -> None:
  op = fields.get("op", "")
  # CONTAINS_OP checks
  if "evict" in op:
    _stats["cache_evict"] = _stats.get("cache_evict", 0) + 1
  if "expire" in op:
    _stats["cache_expire"] = _stats.get("cache_expire", 0) + 1
  if "flush_all" in op:
    _stats["cache_flush"] = _stats.get("cache_flush", 0) + 1
    backend = fields.get("backend", "")
    if "redis" in backend:
      _stats["redis_flush"] = _stats.get("redis_flush", 0) + 1
    if "memcached" in backend:
      _stats["memcached_flush"] = _stats.get("memcached_flush", 0) + 1


def _handle_job(fields: dict[str, str]) -> None:
  status = fields.get("status", "")
  if "completed" in status:
    _stats["job_done"] = _stats.get("job_done", 0) + 1
  if "failed" in status:
    _stats["job_fail"] = _stats.get("job_fail", 0) + 1
    reason = fields.get("reason", "")
    if "timeout" in reason:
      _stats["job_timeout"] = _stats.get("job_timeout", 0) + 1
    if "oom" in reason:
      _stats["job_oom"] = _stats.get("job_oom", 0) + 1
  if "retrying" in status:
    _stats["job_retry"] = _stats.get("job_retry", 0) + 1


_ACTION_HANDLERS: dict[str, object] = {
    "login": _handle_login,
    "query": _handle_query,
    "request": _handle_request,
    "cache_op": _handle_cache,
    "job": _handle_job,
}


def process_event(line: str) -> None:
  """Parse and process a single structured log line.

  Expected format (pipe-delimited):
    SEVERITY|subsystem|action|key1=val1;key2=val2;...

  Example:
    INFO|database|query|sql=SELECT * FROM users;duration=42
  """
  # --- str.split() with a specific delimiter (not hooked) -----------------
  parts = line.split("|")
  if len(parts) < 4:
    return

  severity_str = parts[0].strip()
  subsystem = parts[1].strip()
  action = parts[2].strip()
  raw_fields = parts[3].strip()

  # --- dictionary key lookup (not COMPARE_OP) -----------------------------
  if severity_str not in _SEVERITY_WEIGHTS:
    return
  severity = _SEVERITY_WEIGHTS[severity_str]

  # --- set membership via CONTAINS_OP (not COMPARE_OP) --------------------
  if subsystem not in _KNOWN_SUBSYSTEMS:
    return

  # --- parse key=value pairs using str.split / str.find -------------------
  fields: dict[str, str] = {}
  for pair in raw_fields.split(";"):
    eq_pos = pair.find("=")
    if eq_pos < 0:
      continue
    k = pair[:eq_pos].strip()
    v = pair[eq_pos + 1:].strip()
    # --- str.replace() (not hooked) ---
    v = v.replace("\\n", "\n").replace("\\t", "\t")
    fields[k] = v

  # --- action dispatch via dictionary lookup (not COMPARE_OP) -------------
  handler = _ACTION_HANDLERS.get(action)
  if handler is None:
    return
  handler(fields)

  # --- more CONTAINS_OP / str.find patterns on combined fields ------------
  if severity >= 4:  # ERROR or FATAL
    msg = fields.get("msg", "")
    if "stack_overflow" in msg:
      _stats["stack_overflow"] = _stats.get("stack_overflow", 0) + 1
    if "null_pointer" in msg:
      _stats["null_pointer"] = _stats.get("null_pointer", 0) + 1
    if "segfault" in msg:
      _stats["segfault"] = _stats.get("segfault", 0) + 1
    # str.find on the trace field
    trace = fields.get("trace", "")
    if trace.find("libpthread") >= 0:
      _stats["pthread_crash"] = _stats.get("pthread_crash", 0) + 1
    if trace.find("malloc") >= 0:
      _stats["malloc_crash"] = _stats.get("malloc_crash", 0) + 1

  # --- correlation: subsystem + action combos (all via CONTAINS_OP) -------
  if subsystem in ("auth", "gateway") and action in ("login", "request"):
    token = fields.get("token", "")
    if "expired" in token:
      _stats["expired_token"] = _stats.get("expired_token", 0) + 1
    if "revoked" in token:
      _stats["revoked_token"] = _stats.get("revoked_token", 0) + 1
    ua = fields.get("user_agent", "")
    if "python-requests" in ua:
      _stats["bot_traffic"] = _stats.get("bot_traffic", 0) + 1
    if "curl" in ua:
      _stats["curl_traffic"] = _stats.get("curl_traffic", 0) + 1


def process_batch(text: str) -> None:
  """Process multiple log lines (newline-separated)."""
  for line in text.splitlines():
    line = line.strip()
    if not line:
      continue
    # Skip comment lines (str.find pattern)
    if line.find("//") == 0 or line.find("#") == 0:
      continue
    process_event(line)


# ---------------------------------------------------------------------------
# Fuzzer harness
# ---------------------------------------------------------------------------


def TestOneInput(data: bytes) -> None:
  text = data.decode("utf-8", "ignore")
  try:
    process_batch(text)
  except (ValueError, KeyError, IndexError, OverflowError):
    pass


def main() -> None:
  # Instrument all parser/handler functions.
  atheris.instrument_func(process_batch)
  atheris.instrument_func(process_event)
  atheris.instrument_func(_handle_login)
  atheris.instrument_func(_handle_query)
  atheris.instrument_func(_handle_request)
  atheris.instrument_func(_handle_cache)
  atheris.instrument_func(_handle_job)

  if (
      "ATHERIS_LITERALS_DEBUG" in os.environ
      and hasattr(atheris, "get_string_literals")
  ):
    try:
      lits = atheris.get_string_literals()
      print(f"[DEBUG] registered literals: {len(lits)}", file=sys.stderr)
      if "ATHERIS_LITERALS_SHOW" in os.environ:
        for lit in sorted(lits, key=lambda x: (isinstance(x, bytes), x)):
          print(f"  {lit!r}", file=sys.stderr)
    except Exception:
      pass

  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
