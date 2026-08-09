---
name: add-test
description: Add a unit or regression test to pyasn1 following the suite's strict conventions. Use when writing new tests, adding a regression test for a bug fix, or creating a new test module in this repository.
---

# Adding a test

Full conventions live in [docs/TESTING.md](../../../docs/TESTING.md). This is the
working checklist. If your change establishes a new convention (an assertion
idiom, a layout rule, a cross-codec pattern), update TESTING.md in the same
commit. When you do, cite tests by class and method name (`SomethingTestCase`,
`testThing`), never by line number: line numbers rot with every edit, and the
docs are read by humans as well as agents.

## 1. Decide where the test goes

**Extend an existing module.** This is the default, and correct for almost every
case. `tests/` mirrors the package, so a change in `pyasn1/codec/ber/decoder.py`
gets a test in `tests/codec/ber/test_decoder.py`. Add a new `TestCase` class near
related ones, or a new method to an existing class.

**A new module** is justified when the behavior spans codecs and would otherwise
be copy-pasted into four files. `tests/codec/test_encoder_no_mutation.py` is the
precedent: it lives at the `tests/codec/` level and drives one set of cases
through all five codec entry points.

## 2. If you create a new module, complete every step

Missing the last one is the classic mistake; it fails silently.

- [ ] Six-line copyright header, with a new attribution line for a genuinely new
      file: `# Copyright (c) <year>, Simon Pichugin <simon.pichugin@gmail.com>`
- [ ] `from tests.base import BaseTestCase`, and every `TestCase` subclasses it
- [ ] Import style copied from the **exact module you are editing**, not its
      directory. Only `tests/test_debug.py`, `tests/codec/ber/test_decoder.py` and
      `tests/type/test_tag.py` use `from pyasn1 import error` plus
      `error.PyAsn1Error`; everything else, including the sibling
      `tests/codec/ber/test_encoder.py`, uses
      `from pyasn1.error import PyAsn1Error` plus the bare name
- [ ] Module footer:
      `suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])`
      followed by the `if __name__ == '__main__':` runner
- [ ] **Register the module in the parent `tests/**/__main__.py` suite list.**
      Without this, `unittest discover` runs it but `python -m tests` does not.
      Commit `ca9ec2e` had to add
      `'tests.codec.test_encoder_no_mutation.suite'` to `tests/codec/__main__.py`
      for exactly this reason.

If you override `setUp`, call `BaseTestCase.setUp(self)` as its first statement.

## 3. Write assertions in the house style

Bare `assert`. No `assertRaises`, no pytest; the suite has on the order of 1,600
bare asserts and zero `assertRaises`.

Negative cases use try/except/else, with a message naming what was wrongly
accepted:

```python
try:
    decoder.decode(malicious_payload)
except error.PyAsn1Error:
    pass
else:
    assert 0, 'Excessive continuation octets tolerated'
```

The `else:` clause is the load-bearing part. Without it the test passes even when
nothing raised.

Constraint violations raise `pyasn1.type.error.ValueConstraintError`, which is a
different class from `pyasn1.error.ValueConstraintError`. Catch `PyAsn1Error`
unless you specifically mean one of them.

## 4. If this is a regression test for a security fix

Use the five-part template in
[TESTING.md](../../../docs/TESTING.md#testing-a-security-fix): malicious input
rejected, at-the-limit input still accepted, one-over-the-limit rejected, error
message asserted, and the rejection tests mirrored into `tests/codec/cer/` and
`tests/codec/der/`.

## 5. Verify

```bash
python -Werror -m unittest discover -s tests
```

Then confirm the new module is reachable from the aggregate runner:

```bash
python -m tests
```

**The two commands must report the same number of tests** (the current count
is pinned in [TESTING.md](../../../docs/TESTING.md)). If `python -m tests`
reports fewer than `discover`, your module is missing from a parent
`__main__.py`; go back to step 2.
