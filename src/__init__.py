# Copyright 2021 Google Inc.
# Copyright 2021 Fraunhofer FKIE
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
"""Atheris is a coverage-guided Python fuzzing engine."""

import sys
from typing import Iterable, List, Optional, Tuple

from .function_hooks import _hook_str
from .function_hooks import enabled_hooks
from .function_hooks import gen_match
from .import_hook import instrument_imports

from .instrument_bytecode import instrument_all
from .instrument_bytecode import instrument_func
from .instrument_bytecode import patch_code
from .string_literals import add_literals as _add_string_literals
from .string_literals import clear_literals as _clear_string_literals
from .string_literals import emit_registered_literals as _emit_string_literals
from .string_literals import get_literals as _get_string_literals
from .string_literals import LiteralFilter
from .string_literals import LiteralType
from .string_literals import set_literal_filter as _set_string_literal_filter

# MyPy cannot find native code.
from .native import _reserve_counter  # type: ignore[import]
from .native import _trace_branch  # type: ignore[import]
from .native import _trace_cmp  # type: ignore[import]
from .native import _trace_literal  # type: ignore[import]
from .native import _trace_regex_match  # type: ignore[import]
from .native import ALL_REMAINING  # type: ignore[import]
from .native import build_mode  # type: ignore[import]
from .native import Fuzz  # type: ignore[import]
from .native import FuzzedDataProvider  # type: ignore[import]
from .native import Mutate  # type: ignore[import]
from .native import Setup  # type: ignore[import]
from .native import UpdateCounterArrays  # type: ignore[import]
from .utils import path


# PyInstaller Support
# PyInstaller doesn't automatically support lazy imports, which happens because
# we dynamically decide whether to import the with/without_libfuzzer versions of
# the core module. This function tells it where to look for a hook-atheris.py
# file.


def get_hook_dirs() -> List[str]:
  import os  # pylint: disable=g-import-not-at-top
  return [os.path.dirname(__file__)]


def get_string_literals() -> Tuple[LiteralType, ...]:
  """Returns the registered string/bytes literals."""
  return _get_string_literals()


def add_string_literals(literals: Iterable[LiteralType]) -> None:
  """Registers additional string/bytes literals."""
  _add_string_literals(literals)


def clear_string_literals() -> None:
  """Clears registered string/bytes literals."""
  _clear_string_literals()


def set_string_literal_filter(filter_fn: Optional[LiteralFilter]) -> None:
  """Sets an optional filter for extracted string/bytes literals."""
  _set_string_literal_filter(filter_fn)


def emit_string_literals() -> None:
  """Emits registered literals to the fuzzer mutator."""
  _emit_string_literals(_trace_literal)


# Alias kept for core.cc, which calls atheris._emit_registered_literals().
_emit_registered_literals = emit_string_literals
