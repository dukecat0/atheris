"""Fuzz target: a simple config-file parser.

This is a realistic target that mimics how real-world applications parse
structured text configuration.  It naturally contains many string/bytes
literals in comparisons (section names, directive keywords, option values)
that are hard to discover through random mutation alone but become easily
reachable when the fuzzer has a dictionary of those literals.
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
# A small but realistic config-file parser.
#
# Supports:
#   [section]           -- section headers
#   key = value         -- key-value pairs
#   @include <path>     -- directives
#   @define NAME VALUE  -- macro definitions
#   # comment           -- line comments
#
# Sections recognised: database, server, auth, logging, cache, features
# Each section has its own set of known keys and valid values.
# Several real bugs are embedded behind natural parsing logic.
# ---------------------------------------------------------------------------


class ConfigError(Exception):
  """Raised on invalid configuration."""


class Config:
  """Parsed configuration container."""

  def __init__(self):
    self.sections: dict[str, dict[str, str]] = {}
    self.macros: dict[str, str] = {}
    self.includes: list[str] = []
    self._current_section: str | None = None


def _parse_directive(line: str, config: Config) -> None:
  """Handle lines starting with '@'."""
  parts = line.split(None, 2)
  directive = parts[0]

  if directive == "@include":
    if len(parts) < 2:
      raise ConfigError("@include requires a path")
    path = parts[1].strip('"').strip("'")
    if path.startswith("/etc/") or path.startswith("/opt/"):
      config.includes.append(path)
    elif path.startswith("~/.config/"):
      config.includes.append(path)
    elif path.startswith("./") or path.startswith("../"):
      config.includes.append(path)
    else:
      raise ConfigError(f"Unsafe include path: {path}")

  elif directive == "@define":
    if len(parts) < 3:
      raise ConfigError("@define requires NAME and VALUE")
    name, value = parts[1], parts[2]
    if not name.isupper():
      raise ConfigError(f"Macro names must be uppercase: {name}")
    config.macros[name] = value

  elif directive == "@version":
    if len(parts) < 2:
      raise ConfigError("@version requires a version string")
    version = parts[1]
    major, _, rest = version.partition(".")
    minor, _, patch = rest.partition(".")
    # Bug: unchecked int conversion can raise on garbage input
    maj = int(major)
    if maj < 1 or maj > 5:
      raise ConfigError(f"Unsupported config version: {maj}")

  elif directive == "@encoding":
    if len(parts) < 2:
      raise ConfigError("@encoding requires a value")
    enc = parts[1].lower()
    if enc not in ("utf-8", "ascii", "latin-1", "utf-16"):
      raise ConfigError(f"Unsupported encoding: {enc}")

  else:
    raise ConfigError(f"Unknown directive: {directive}")


def _validate_database(key: str, value: str) -> None:
  """Validate keys in the [database] section."""
  if key == "engine":
    if value not in ("postgresql", "mysql", "sqlite", "mariadb"):
      raise ConfigError(f"Unknown database engine: {value}")
  elif key == "host":
    if not value or len(value) > 253:
      raise ConfigError("Invalid hostname")
  elif key == "port":
    port = int(value)
    if port < 1 or port > 65535:
      raise ConfigError(f"Port out of range: {port}")
  elif key == "name":
    if not value.isidentifier():
      raise ConfigError(f"Invalid database name: {value}")
  elif key == "pool_size":
    size = int(value)
    # Bug: signed comparison allows negative pool sizes
    if size > 100:
      raise ConfigError(f"Pool too large: {size}")
  elif key == "ssl_mode":
    if value not in ("disable", "require", "verify-ca", "verify-full"):
      raise ConfigError(f"Unknown ssl_mode: {value}")
  elif key == "timeout":
    timeout = float(value)
    if timeout <= 0:
      raise ConfigError("Timeout must be positive")


def _validate_server(key: str, value: str) -> None:
  """Validate keys in the [server] section."""
  if key == "bind":
    if value not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
      # Accept dotted-quad addresses
      parts = value.split(".")
      if len(parts) != 4:
        raise ConfigError(f"Invalid bind address: {value}")
  elif key == "workers":
    w = int(value)
    if w < 1 or w > 64:
      raise ConfigError(f"Invalid worker count: {w}")
  elif key == "mode":
    if value not in ("development", "production", "staging", "testing"):
      raise ConfigError(f"Unknown server mode: {value}")
  elif key == "log_level":
    if value.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
      raise ConfigError(f"Unknown log level: {value}")
  elif key == "max_request_size":
    # Bug: no overflow check on extremely large values
    size = int(value)
    buf = bytearray(min(size, 1024))  # noqa: F841


def _validate_auth(key: str, value: str) -> None:
  """Validate keys in the [auth] section."""
  if key == "method":
    if value not in ("token", "oauth2", "basic", "ldap", "saml", "certificate"):
      raise ConfigError(f"Unknown auth method: {value}")
  elif key == "token_prefix":
    if value not in ("Bearer", "Token", "Api-Key", "JWT"):
      raise ConfigError(f"Unknown token prefix: {value}")
  elif key == "session_ttl":
    ttl = int(value)
    if ttl < 60 or ttl > 86400:
      raise ConfigError(f"Session TTL out of range: {ttl}")
  elif key == "secret_key":
    if len(value) < 16:
      raise ConfigError("Secret key too short")
    # Bug: secret key stored as-is (no hashing)
  elif key == "allowed_origins":
    origins = value.split(",")
    for origin in origins:
      origin = origin.strip()
      if not (origin.startswith("http://") or origin.startswith("https://")):
        raise ConfigError(f"Origin must start with http(s)://: {origin}")


def _validate_logging(key: str, value: str) -> None:
  """Validate keys in the [logging] section."""
  if key == "format":
    if value not in ("json", "text", "structured", "syslog"):
      raise ConfigError(f"Unknown log format: {value}")
  elif key == "output":
    if value not in ("stdout", "stderr", "file", "syslog", "journald"):
      raise ConfigError(f"Unknown log output: {value}")
  elif key == "file_path":
    if not (value.startswith("/var/log/") or value.startswith("./logs/")):
      raise ConfigError(f"Log path not in allowed directory: {value}")
  elif key == "rotation":
    if value not in ("daily", "weekly", "size", "none"):
      raise ConfigError(f"Unknown rotation policy: {value}")
  elif key == "max_size_mb":
    mb = int(value)
    if mb < 1 or mb > 10240:
      raise ConfigError(f"Max log size out of range: {mb}")


def _validate_cache(key: str, value: str) -> None:
  """Validate keys in the [cache] section."""
  if key == "backend":
    if value not in ("redis", "memcached", "memory", "disk", "none"):
      raise ConfigError(f"Unknown cache backend: {value}")
  elif key == "ttl":
    ttl = int(value)
    if ttl < 0:
      raise ConfigError(f"Negative TTL: {ttl}")
  elif key == "prefix":
    if not value.isidentifier():
      raise ConfigError(f"Invalid cache prefix: {value}")
  elif key == "serializer":
    if value not in ("json", "pickle", "msgpack", "protobuf"):
      raise ConfigError(f"Unknown serializer: {value}")


def _validate_features(key: str, value: str) -> None:
  """Validate keys in the [features] section."""
  if key not in (
      "enable_experimental",
      "enable_beta",
      "dark_mode",
      "telemetry",
      "auto_update",
      "notifications",
  ):
    raise ConfigError(f"Unknown feature flag: {key}")
  if value.lower() not in ("true", "false", "on", "off", "1", "0"):
    raise ConfigError(f"Feature flag must be boolean: {value}")


_SECTION_VALIDATORS = {
  "database": _validate_database,
  "server": _validate_server,
  "auth": _validate_auth,
  "logging": _validate_logging,
  "cache": _validate_cache,
  "features": _validate_features,
}


def parse_config(text: str) -> Config:
  """Parse a configuration file from text.

  This is the main entry point that the fuzzer exercises.
  """
  config = Config()

  for lineno, raw_line in enumerate(text.splitlines(), 1):
    line = raw_line.strip()

    # Skip empty lines and comments.
    if not line or line.startswith("#"):
      continue

    # Directives.
    if line.startswith("@"):
      _parse_directive(line, config)
      continue

    # Section header.
    if line.startswith("[") and line.endswith("]"):
      section_name = line[1:-1].strip().lower()
      if section_name not in _SECTION_VALIDATORS:
        raise ConfigError(
            f"Line {lineno}: unknown section [{section_name}]"
        )
      config._current_section = section_name
      if section_name not in config.sections:
        config.sections[section_name] = {}
      continue

    # Key = value.
    if "=" in line:
      if config._current_section is None:
        raise ConfigError(
            f"Line {lineno}: key-value pair outside of section"
        )
      key, _, value = line.partition("=")
      key = key.strip().lower()
      value = value.strip().strip('"').strip("'")

      # Macro expansion.
      for macro_name, macro_value in config.macros.items():
        value = value.replace(f"${{{macro_name}}}", macro_value)

      # Validate against section-specific rules.
      validator = _SECTION_VALIDATORS.get(config._current_section)
      if validator:
        validator(key, value)

      config.sections[config._current_section][key] = value
      continue

    raise ConfigError(f"Line {lineno}: unrecognised syntax")

  return config


# ---------------------------------------------------------------------------
# Fuzzer harness
# ---------------------------------------------------------------------------


def TestOneInput(data: bytes) -> None:
  text = data.decode("utf-8", "ignore")
  try:
    parse_config(text)
  except (ConfigError, ValueError, OverflowError):
    pass


def main() -> None:
  # Instrument the parser functions so their string literals are registered.
  atheris.instrument_func(parse_config)
  atheris.instrument_func(_parse_directive)
  atheris.instrument_func(_validate_database)
  atheris.instrument_func(_validate_server)
  atheris.instrument_func(_validate_auth)
  atheris.instrument_func(_validate_logging)
  atheris.instrument_func(_validate_cache)
  atheris.instrument_func(_validate_features)

  if (
      "ATHERIS_LITERALS_DEBUG" in os.environ
      and hasattr(atheris, "get_string_literals")
  ):
    try:
      lits = atheris.get_string_literals()
      print(f"[DEBUG] registered literals: {len(lits)}", file=sys.stderr)
    except Exception:
      pass

  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
