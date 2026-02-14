from __future__ import annotations

import base64
import json
import re
import sys
import urllib.parse

try:
  import atheris
except ImportError:  # pragma: no cover
  # Allow running directly from a source checkout without installing.
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


# A manual target designed to benefit from literal/dictionary guidance.
# It contains many embedded string/bytes literals and gated branches that are
# unlikely to be reached with purely random mutations.

HTTP_METHODS = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
)

HEADER_NAMES = (
    "Content-Type",
    "User-Agent",
    "X-Api-Key",
    "X-Exploit",
    "X-Mode",
    "X-Debug",
)

CONTENT_TYPES = (
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
)

# Bytes magic that tends to be useful for real-world parsers.
MAGIC_BYTES = (
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"PK\x03\x04",  # zip
)

SQL_KEYWORDS = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "FROM",
    "WHERE",
    "JOIN",
    "UNION",
    "DROP",
)


def _parse_headers(text: str) -> dict[str, str]:
  headers: dict[str, str] = {}
  for line in text.split("\n"):
    if ":" not in line:
      continue
    name, value = line.split(":", 1)
    name = name.strip()
    value = value.strip()
    if name:
      headers[name] = value
  return headers


def _interesting_branching_logic(data: bytes) -> None:
  # Help Atheris by ensuring this code gets instrumented.
  # (instrument_func will patch code objects and register literals.)
  text = data.decode("utf-8", "ignore")

  # Gate 1: looks like an HTTP request.
  first_line = text.split("\n", 1)[0]
  if not any(first_line.startswith(m + " ") for m in HTTP_METHODS):
    return

  # Gate 2: requires a plausible path and query.
  if " HTTP/1.1" not in first_line and " HTTP/2" not in first_line:
    return

  # Parse the path.
  parts = first_line.split(" ")
  if len(parts) < 2:
    return
  path = parts[1]

  # Gate 3: focus on a few realistic endpoints.
  if not (path.startswith("/api/") or path.startswith("/v1/") or path.startswith("/admin/")):
    return

  # Split headers/body.
  head, _, body = text.partition("\n\n")
  headers = _parse_headers(head)

  # Gate 4: require some known header names.
  if not any(h in headers for h in HEADER_NAMES):
    return

  mode = headers.get("X-Mode", "")
  if mode not in ("fast", "safe", "debug"):
    return

  # Query string parsing — introduces lots of structured branches.
  query = ""
  if "?" in path:
    _, query = path.split("?", 1)

  qs = urllib.parse.parse_qs(query, keep_blank_values=True)

  # Gate 5: require specific parameters.
  if "action" not in qs or "id" not in qs:
    return

  action = (qs.get("action") or [""])[0]
  if action not in ("create", "update", "delete", "preview"):
    return

  # Gate 6: magic bytes condition.
  if not any(m in data for m in MAGIC_BYTES):
    return

  content_type = headers.get("Content-Type", "")
  if content_type not in CONTENT_TYPES:
    return

  # Body parsing: JSON, form, or plain.
  if content_type == "application/json":
    # Gate 7: must look like JSON.
    if not (body.lstrip().startswith("{") and body.rstrip().endswith("}")):
      return
    try:
      obj = json.loads(body)
    except Exception:
      return

    # Gate 8: require nested keys.
    if not isinstance(obj, dict):
      return
    if obj.get("type") not in ("job", "task", "report"):
      return
    meta = obj.get("meta")
    if not isinstance(meta, dict):
      return

    token = meta.get("token", "")
    if not isinstance(token, str) or not token.startswith("tok_"):
      return

    # Gate 9: base64 branch.
    payload = obj.get("payload", "")
    if not isinstance(payload, str) or not payload.startswith("b64:"):
      return

    try:
      decoded = base64.b64decode(payload[4:], validate=False)
    except Exception:
      return

    # Gate 10: regex branch that benefits from dictionary literals.
    # (Avoid catastrophic patterns; keep it simple.)
    if not re.search(r"^ID-[0-9a-f]{8}$", decoded.decode("ascii", "ignore")):
      return

    # Intentional “bug” trigger to measure time-to-reach.
    # Needs multiple conditions so it won’t be hit immediately.
    if headers.get("X-Exploit") == "0xdeadbeef" and obj.get("type") == "report":
      raise RuntimeError("Intentional crash: reached deep JSON + literal path")

  elif content_type == "application/x-www-form-urlencoded":
    form = urllib.parse.parse_qs(body, keep_blank_values=True)
    if (form.get("user") or [""])[0] != "admin":
      return

    # Gate via SQL-ish keywords.
    stmt = (form.get("q") or [""])[0]
    if not any(k in stmt.upper() for k in SQL_KEYWORDS):
      return

    if headers.get("X-Debug") == "1" and "DROP" in stmt.upper():
      raise RuntimeError("Intentional crash: reached form + SQL-ish path")

  else:
    # Plain text branch.
    if "BEGIN" not in body.upper() or "COMMIT" not in body.upper():
      return


def TestOneInput(data: bytes) -> None:
  _interesting_branching_logic(data)


def main() -> None:
  # Ensure our own target code is instrumented (and thus literals registered).
  atheris.instrument_func(_interesting_branching_logic)
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
