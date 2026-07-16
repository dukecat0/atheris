# Copyright 2025 Google LLC
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
"""Tests for string literal aggregation during instrumentation."""

import logging
import os
import tempfile
import types
import unittest

import atheris
from atheris import instrument_bytecode

_logger = logging.getLogger(__name__)


class StringLiteralAggregationTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    atheris.clear_string_literals()

  def tearDown(self):
    atheris.clear_string_literals()
    instrument_bytecode.collect_string_literals(False)
    super().tearDown()

  def _collect(self, func):
    instrument_bytecode._collect_code_literals(func.__code__)
    return atheris.get_string_literals()

  def _collect_source(self, source):
    """Compiles a module source and collects literals from all code objects."""

    def walk(code):
      instrument_bytecode._collect_code_literals(code)
      for const in code.co_consts:
        if isinstance(const, types.CodeType):
          walk(const)

    walk(compile(source, "<string_literals_test>", "exec"))
    return atheris.get_string_literals()

  def test_collects_literals_from_many_contexts(self):
    def target(x):
      if x == "equality":
        return 1
      if x.startswith("prefix"):
        return 2
      if "membership" in x:
        return 3
      return x.find("find_arg")

    literals = self._collect(target)
    for expected in [b"equality", b"prefix", b"membership", b"find_arg"]:
      self.assertIn(expected, literals)

  def test_collects_bytes_literals(self):
    def target(x):
      return x == b"some_bytes"

    self.assertIn(b"some_bytes", self._collect(target))

  def test_collects_literals_from_constant_tuples(self):
    def target(x):
      return x.startswith(("tuple_a", "tuple_b"))

    literals = self._collect(target)
    self.assertIn(b"tuple_a", literals)
    self.assertIn(b"tuple_b", literals)

  def test_deduplicates_and_preserves_order(self):
    def target(x):
      return x == "first" or x == "second" or x == "first"

    literals = self._collect(target)
    self.assertEqual(literals.count(b"first"), 1)
    self.assertLess(literals.index(b"first"), literals.index(b"second"))

  def test_filters_short_literals_and_marker(self):
    def target(x):
      # "a" is below the minimum length; the instrumentation marker must never
      # be collected.
      return x == "a" or x == "__ATHERIS_INSTRUMENTED__"

    literals = self._collect(target)
    self.assertNotIn(b"a", literals)
    self.assertNotIn(b"__ATHERIS_INSTRUMENTED__", literals)

  def test_ignores_logging_only_literals(self):
    def target(x):
      logging.info("logging_only_a")
      _logger.debug("logging_only_b %s", x)
      if x == "kept_literal":
        return 1
      return 0

    literals = self._collect(target)
    self.assertIn(b"kept_literal", literals)
    self.assertNotIn(b"logging_only_a", literals)
    self.assertNotIn(b"logging_only_b %s", literals)

  def test_ignores_logging_on_attribute_receiver(self):
    class Service:

      def handle(self, x):
        self.log.error("attr_logging_only")
        return x == "attr_kept"

    literals = self._collect(Service.handle)
    self.assertIn(b"attr_kept", literals)
    self.assertNotIn(b"attr_logging_only", literals)

  def test_keeps_literal_used_outside_logging(self):
    def target(x):
      logging.warning("shared_literal")
      return x == "shared_literal"

    self.assertIn(b"shared_literal", self._collect(target))

  def test_keeps_literals_for_non_logger_receivers(self):
    def target(parser, x):
      # A method named like a logging level, but on a non-logger receiver,
      # must not be treated as a logging call.
      parser.error("argparse_message")
      return x

    self.assertIn(b"argparse_message", self._collect(target))

  def test_collects_returned_literal(self):
    # On Python 3.12/3.13 `return "literal"` compiles to RETURN_CONST rather
    # than LOAD_CONST + RETURN_VALUE.
    def target(x):
      return "returned_literal"

    self.assertIn(b"returned_literal", self._collect(target))

  def test_ignores_module_docstring(self):
    literals = self._collect_source(
        '"""module docstring noise"""\nMAGIC = "kept_module_literal"\n'
    )
    self.assertIn(b"kept_module_literal", literals)
    self.assertNotIn(b"module docstring noise", literals)

  def test_ignores_class_docstring_and_machinery(self):
    literals = self._collect_source(
        "class SomeService:\n"
        '  """class docstring noise"""\n'
        '  marker = "kept_class_literal"\n'
        "  def __init__(self):\n"
        '    self.tracked_attribute = "kept_attr_value"\n'
    )
    self.assertIn(b"kept_class_literal", literals)
    self.assertIn(b"kept_attr_value", literals)
    self.assertNotIn(b"class docstring noise", literals)
    # The class name is stored into __qualname__ by the class machinery, and
    # on Python 3.13+ attribute names are stored into __static_attributes__.
    self.assertNotIn(b"SomeService", literals)
    self.assertNotIn(b"tracked_attribute", literals)

  def test_ignores_dunder_metadata_assignments(self):
    literals = self._collect_source('__version__ = "9.9.9_test_version"\n')
    self.assertNotIn(b"9.9.9_test_version", literals)

  def test_ignores_annotation_names(self):
    literals = self._collect_source(
        "def process(data: bytes, count: int = 3) -> None:\n"
        '  if b"kept_body_token" in data:\n'
        "    raise RuntimeError()\n"
    )
    self.assertIn(b"kept_body_token", literals)
    self.assertNotIn(b"data", literals)
    self.assertNotIn(b"count", literals)
    self.assertNotIn(b"return", literals)

  def test_ignores_future_style_annotations(self):
    literals = self._collect_source(
        "from __future__ import annotations\n"
        "def process(data: bytes) -> SomeCustomType:\n"
        "  return data\n"
    )
    self.assertNotIn(b"data", literals)
    self.assertNotIn(b"bytes", literals)
    self.assertNotIn(b"return", literals)
    self.assertNotIn(b"SomeCustomType", literals)

  def test_keeps_default_value_next_to_annotations(self):
    literals = self._collect_source(
        'def lookup(name: str = "fallback_name") -> str:\n'
        "  return name\n"
    )
    self.assertIn(b"fallback_name", literals)
    self.assertNotIn(b"name", literals)
    self.assertNotIn(b"return", literals)

  def test_keeps_literal_matching_annotation_name_used_in_body(self):
    literals = self._collect_source(
        "def handle(data: bytes) -> int:\n"
        '  return 1 if b"data" in data else 0\n'
    )
    self.assertIn(b"data", literals)

  def test_disabled_by_default(self):
    self.assertFalse(instrument_bytecode._collect_literals)
    instrument_bytecode.collect_string_literals()
    self.assertTrue(instrument_bytecode._collect_literals)
    instrument_bytecode.collect_string_literals(False)
    self.assertFalse(instrument_bytecode._collect_literals)

  def test_write_dictionary_format(self):
    instrument_bytecode._register_literal("plain")
    instrument_bytecode._register_literal('has"quote')
    instrument_bytecode._register_literal(b"\x00\xff")

    path = os.path.join(tempfile.mkdtemp(), "atheris.dict")
    count = atheris.write_dictionary(path)
    self.assertEqual(count, 3)

    with open(path) as f:
      lines = f.read().splitlines()

    self.assertIn('"plain"', lines)
    self.assertIn('"has\\"quote"', lines)
    self.assertIn('"\\x00\\xff"', lines)

  def test_escape_dictionary_entry(self):
    self.assertEqual(
        instrument_bytecode._escape_dictionary_entry(b"abc"), '"abc"'
    )
    self.assertEqual(
        instrument_bytecode._escape_dictionary_entry(b"a\\b"), '"a\\\\b"'
    )
    self.assertEqual(
        instrument_bytecode._escape_dictionary_entry(b"tab\there"),
        '"tab\\x09here"',
    )


if __name__ == "__main__":
  unittest.main()
