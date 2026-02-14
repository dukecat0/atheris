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
"""Tests for the string_literals module."""

import unittest

from atheris import string_literals


def _make_code_with_consts(*consts, filename="test.py"):
  """Create a minimal code object whose co_consts contains *consts*."""
  # Build a trivial code object with the desired constants.
  base = compile("x = 0", filename, "exec")
  return base.replace(co_consts=consts)


class RegisterFromCodeTest(unittest.TestCase):
  """Tests for register_from_code()."""

  def setUp(self):
    string_literals.clear_literals()
    # Re-enable default filter for every test.
    string_literals.set_literal_filter(string_literals.default_literal_filter)

  def test_registers_plain_string(self):
    code = _make_code_with_consts("hello", "world")
    string_literals.register_from_code(code)
    lits = string_literals.get_literals()
    self.assertIn("hello", lits)
    self.assertIn("world", lits)

  def test_registers_bytes(self):
    code = _make_code_with_consts(b"deadbeef")
    string_literals.register_from_code(code)
    self.assertIn(b"deadbeef", string_literals.get_literals())

  def test_ignores_non_string_consts(self):
    code = _make_code_with_consts(42, 3.14, None, True)
    string_literals.register_from_code(code)
    self.assertEqual(len(string_literals.get_literals()), 0)

  def test_deduplicates(self):
    code = _make_code_with_consts("dup", "dup", "dup")
    string_literals.register_from_code(code)
    count = sum(1 for l in string_literals.get_literals() if l == "dup")
    self.assertEqual(count, 1)


class FormatStringFilterTest(unittest.TestCase):
  """Tests for _looks_like_format_string() via the default filter."""

  def setUp(self):
    string_literals.clear_literals()
    string_literals.set_literal_filter(string_literals.default_literal_filter)

  def test_filters_percent_format(self):
    code = _make_code_with_consts("Processing %d items from %s")
    string_literals.register_from_code(code)
    self.assertNotIn("Processing %d items from %s",
                     string_literals.get_literals())

  def test_filters_brace_format(self):
    code = _make_code_with_consts("Hello {name}, you have {count} messages")
    string_literals.register_from_code(code)
    self.assertNotIn("Hello {name}, you have {count} messages",
                     string_literals.get_literals())

  def test_keeps_short_strings_with_braces(self):
    # Strings shorter than _FORMAT_MIN_LENGTH are not considered format noise.
    code = _make_code_with_consts("{x}")
    string_literals.register_from_code(code)
    self.assertIn("{x}", string_literals.get_literals())

  def test_keeps_normal_strings(self):
    code = _make_code_with_consts("startswith_target", b"some bytes")
    string_literals.register_from_code(code)
    lits = string_literals.get_literals()
    self.assertIn("startswith_target", lits)
    self.assertIn(b"some bytes", lits)


class LoggingModuleFilterTest(unittest.TestCase):
  """Tests that literals from logging module code objects are dropped."""

  def setUp(self):
    string_literals.clear_literals()
    string_literals.set_literal_filter(string_literals.default_literal_filter)

  def test_filters_logging_module_literals(self):
    import logging
    # Use a real code object from the logging module.
    code = logging.Logger.info.__code__
    string_literals.register_from_code(code)
    # Nothing from the logging module should be registered.
    self.assertEqual(len(string_literals.get_literals()), 0)


class CustomFilterTest(unittest.TestCase):
  """Tests for set_literal_filter()."""

  def setUp(self):
    string_literals.clear_literals()

  def test_custom_filter_rejects_all(self):
    string_literals.set_literal_filter(lambda lit, code: False)
    code = _make_code_with_consts("should_be_dropped")
    string_literals.register_from_code(code)
    self.assertEqual(len(string_literals.get_literals()), 0)

  def test_custom_filter_accepts_all(self):
    string_literals.set_literal_filter(lambda lit, code: True)
    code = _make_code_with_consts("Processing %d items from %s")
    string_literals.register_from_code(code)
    # The format string would normally be filtered, but our custom filter
    # accepts everything.
    self.assertIn("Processing %d items from %s",
                  string_literals.get_literals())

  def test_none_filter_accepts_all(self):
    string_literals.set_literal_filter(None)
    code = _make_code_with_consts("anything", "Processing %d stuff")
    string_literals.register_from_code(code)
    lits = string_literals.get_literals()
    self.assertIn("anything", lits)
    self.assertIn("Processing %d stuff", lits)

  def tearDown(self):
    # Restore default filter.
    string_literals.set_literal_filter(string_literals.default_literal_filter)


class EmitLiteralsTest(unittest.TestCase):
  """Tests for emit_registered_literals()."""

  def setUp(self):
    string_literals.clear_literals()
    string_literals.set_literal_filter(None)

  def test_emits_each_literal_once(self):
    emitted = []
    string_literals.add_literals(["foo", "bar"])
    string_literals.emit_registered_literals(lambda lit: emitted.append(lit))
    self.assertIn("foo", emitted)
    self.assertIn("bar", emitted)
    self.assertEqual(len(emitted), 2)

  def test_does_not_re_emit(self):
    emitted = []
    string_literals.add_literals(["baz"])
    string_literals.emit_registered_literals(lambda lit: emitted.append(lit))
    emitted.clear()
    # Second call should not re-emit.
    string_literals.emit_registered_literals(lambda lit: emitted.append(lit))
    self.assertEqual(len(emitted), 0)

  def tearDown(self):
    string_literals.set_literal_filter(string_literals.default_literal_filter)


class AddAndClearTest(unittest.TestCase):
  """Tests for add_literals() and clear_literals()."""

  def setUp(self):
    string_literals.clear_literals()

  def test_add_literals(self):
    string_literals.add_literals(["alpha", b"beta"])
    lits = string_literals.get_literals()
    self.assertIn("alpha", lits)
    self.assertIn(b"beta", lits)

  def test_clear_literals(self):
    string_literals.add_literals(["gamma"])
    string_literals.clear_literals()
    self.assertEqual(len(string_literals.get_literals()), 0)

  def test_clear_resets_emitted_tracking(self):
    emitted = []
    string_literals.add_literals(["delta"])
    string_literals.emit_registered_literals(lambda lit: emitted.append(lit))
    emitted.clear()
    # After clear + re-add, it should emit again.
    string_literals.clear_literals()
    string_literals.add_literals(["delta"])
    string_literals.emit_registered_literals(lambda lit: emitted.append(lit))
    self.assertIn("delta", emitted)


if __name__ == "__main__":
  unittest.main()
