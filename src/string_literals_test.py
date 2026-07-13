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

import os
import tempfile
import unittest

import atheris
from atheris import instrument_bytecode


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
