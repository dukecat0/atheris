# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Registry for extracted string and bytes literals."""

from __future__ import annotations

import logging
import os
import re
from typing import Callable, Iterable, Optional, Set, Tuple, Union
import types

LiteralType = Union[str, bytes]
LiteralFilter = Callable[[LiteralType, types.CodeType], bool]

_REGISTERED_LITERALS: Set[LiteralType] = set()
_EMITTED_LITERALS: Set[LiteralType] = set()
_LITERAL_FILTER: Optional[LiteralFilter] = None

# Paths that belong to the logging module — resolved once.
_LOGGING_PATHS: Tuple[str, ...] = tuple(
    os.path.dirname(os.path.abspath(f))
    for f in (logging.__file__,)
    if f is not None
)

# Regex matching common format-string patterns used with logging / str.format.
_FORMAT_PATTERN = re.compile(
    r"%[#0\- +]?[0-9*]*\.?[0-9*]*[hlLqjzt]*[diouxXeEfFgGcrsab%]"
    r"|\{[^}]*\}"
)

# Minimum length for a format-looking literal to be considered noise.
_FORMAT_MIN_LENGTH = 6


def _is_from_logging_module(code: types.CodeType) -> bool:
  """Returns True if *code* lives inside the stdlib logging package."""
  filename = os.path.abspath(code.co_filename) if code.co_filename else ""
  return any(filename.startswith(p) for p in _LOGGING_PATHS)


def _looks_like_format_string(literal: LiteralType) -> bool:
  """Heuristic: returns True if the literal looks like a log format string."""
  text = literal.decode("utf-8", "ignore") if isinstance(literal, bytes) else literal
  if len(text) < _FORMAT_MIN_LENGTH:
    return False
  return bool(_FORMAT_PATTERN.search(text))


def default_literal_filter(literal: LiteralType, code: types.CodeType) -> bool:
  """Built-in filter: drops logging-module internals and format strings."""
  if _is_from_logging_module(code):
    return False
  if _looks_like_format_string(literal):
    return False
  return True


# Enable the default filter on import.
_LITERAL_FILTER = default_literal_filter


def register_from_code(code: types.CodeType) -> None:
  for const in code.co_consts:
    if isinstance(const, (str, bytes)):
      if _LITERAL_FILTER is not None and not _LITERAL_FILTER(const, code):
        continue
      _REGISTERED_LITERALS.add(const)


def set_literal_filter(filter_fn: Optional[LiteralFilter]) -> None:
  global _LITERAL_FILTER
  _LITERAL_FILTER = filter_fn


def clear_literals() -> None:
  _REGISTERED_LITERALS.clear()
  _EMITTED_LITERALS.clear()


def get_literals() -> Tuple[LiteralType, ...]:
  return tuple(_REGISTERED_LITERALS)


def add_literals(literals: Iterable[LiteralType]) -> None:
  for literal in literals:
    _REGISTERED_LITERALS.add(literal)


def emit_registered_literals(trace_literal_fn: Callable[[LiteralType], None]) -> None:
  new_literals = _REGISTERED_LITERALS - _EMITTED_LITERALS
  for literal in new_literals:
    trace_literal_fn(literal)
  _EMITTED_LITERALS.update(new_literals)
