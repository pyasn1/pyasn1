# pyasn1 testing guide

How this suite is built, and what a new test must look like to fit it. The
conventions here are not stylistic preferences; several of them are the
difference between a test that runs in CI and one that silently never executes.

This file lives at `docs/TESTING.md`, deliberately outside the Sphinx source
tree (`docs/source/`). See the placement note in
[ARCHITECTURE.md](ARCHITECTURE.md) for why.

Code and tests are cited by symbol: file plus test class, method or `tox.ini`
section, never line numbers. Line numbers rot with every edit, and this guide
serves human readers as much as agents. If a change renames a cited symbol or
alters a convention described here, update this file in the same commit. If a
cited symbol is missing, the code has moved or changed; re-verify the claim
rather than deleting the reference.

## Running the suite

Use the form CI uses:

```bash
python -Werror -m unittest discover -s tests
```

The `-Werror` is the important part, and it lives only on the `commands` line
of `[testenv]` in `tox.ini`, not in any GitHub Actions workflow. Running plain
`python -m unittest discover -s tests` will pass locally on changes that fail
CI, because every warning raised during a test is an error under the real gate.
The most common way to trip this is touching a deprecated module attribute
(`decoder.tagMap` / `encoder.typeMap`), which raises `DeprecationWarning`; use
`TAG_MAP` / `TYPE_MAP` instead.

A single module, for quick iteration:

```bash
python -m unittest tests.type.test_univ
```

There is also a hand-registered aggregate runner, `python -m tests`, discussed
under [suite registration](#suite-registration-the-silent-failure) below. It
and `discover` should always report the same test count; both currently report
1261 tests. A divergence means a module is missing from a `__main__.py` list.

### The gates, and which Python version runs each

Everything is driven by `tox.ini`; the workflow just installs tox and
`tox-gh-actions` and calls `python -m tox`.

| Env | Command | Gate |
|-----|---------|------|
| `py38`…`py314`, `pypy38`…`pypy310` | `{envpython} -Werror -m unittest discover -s tests` (`[testenv]`) | any warning fails |
| `cover` | `coverage run --source pyasn1 -m unittest discover` then `coverage report --fail-under 80` (`[testenv:cover]`) | coverage ≥ 80% |
| `bandit` | `bandit -r pyasn1 -c .bandit.yml` (`[testenv:bandit]`) | scans `pyasn1/` only, never `tests/` |
| `docs` | `make -C docs html SPHINXOPTS="-W --keep-going"` (`[testenv:docs]`) | any Sphinx warning fails |
| `build` | `python -m build` + `twine check --strict` on both artifacts (`[testenv:build]`) | README must render |

Two traps hide in that table.

The `cover` env is not the same run as the `py3xx` envs. It omits `-Werror`
and it omits `-s tests`, so discovery starts from the repository root rather
than `tests/` (the `[testenv:cover]` command). A green `tox -e cover`
therefore does not prove the `-Werror` gate passes.

The `[gh-actions]` mapping in `tox.ini` pins the non-test envs to single
matrix legs: `docs` runs only under Python 3.9, and `cover`, `build` and
`bandit` only under Python 3.10. Removing or renaming a matrix entry in
`.github/workflows/main.yml` silently drops the corresponding gate; CI stays
green while no longer checking coverage, security or documentation.

`tox` itself is not installed in a fresh checkout. Install it before relying
on any row above, and never report a gate as passing that you did not run.

## Anatomy of a test module

Every test module follows the same skeleton. Copy it exactly.

```python
#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import univ


class SomethingTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)
        # per-test fixtures here

    def testThing(self):
        assert univ.Integer(1) == 1


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
```

**The copyright header.** Existing files carry the Ilya Etingof attribution
verbatim (2005-2020, or 2005-2019 in `tests/codec/test_streaming.py`); leave
those alone. A genuinely new module gets the same
six-line block with a new attribution line, as the header block of
`tests/codec/test_encoder_no_mutation.py` does.

**`BaseTestCase` is mandatory.** It installs a null debug logger in `setUp`
and clears it in `tearDown` (`tests/base.py`). The consequence is worth
internalizing: the whole suite — bar `NonStreamingCompatibilityTestCase` in
`tests/codec/ber/test_decoder.py`, whose `setUp` deliberately undoes the
logger — runs with pyasn1's debug logging *enabled* and its output discarded,
so every `if LOG:` branch in the codecs actually executes, and a malformed
logging format string is a test failure rather than dead code. If you override `setUp`, you must call `BaseTestCase.setUp(self)`
first, or you leak logger state into the rest of the suite.

**Import style varies by file, not by directory.** Copy the spelling used by
the exact module you are editing. Only three modules use the module-import
form (`tests/test_debug.py`, `tests/codec/ber/test_decoder.py` and
`tests/type/test_tag.py`), writing `from pyasn1 import error` and then
`error.PyAsn1Error`. Everything else, *including the sibling
`tests/codec/ber/test_encoder.py`*, uses `from pyasn1.error import
PyAsn1Error` and the bare name. A single security fix has been written both
ways in the same commit because it touched files on both sides of that split.
Imports are one `from … import …` per line; the lone comma-joined exception
is the paired Unicode-error import in `tests/type/test_univ.py`.

### Suite registration: the silent failure

`unittest discover` finds any `test_*.py`. The aggregate runner
`python -m tests` does not; it loads a hand-maintained list of module names.
Each package has a `__main__.py` whose `suite` list enumerates its children:

- the `suite` list in `tests/__main__.py` → `test_debug`, `tests.type`, `tests.codec`
- the `suite` list in `tests/codec/__main__.py` → the two cross-codec modules plus the four codec packages
- the `suite` list in `tests/codec/ber/__main__.py` → `test_encoder`, `test_decoder`

**Adding a new test module means editing the parent `__main__.py` too.** When
`tests/codec/test_encoder_no_mutation.py` was added in commit `ca9ec2e`, the
commit also had to add `'tests.codec.test_encoder_no_mutation.suite'` to
`tests/codec/__main__.py`. Skip that step and the module is invisible to
`python -m tests` while still passing under `discover`: the failure mode is
silence, not an error.

## Assertion idioms

This suite uses bare `assert` statements and almost nothing else. It currently
holds about 1,600 bare asserts against a handful of `self.assertIs` calls,
zero `assertRaises`, and no pytest anywhere. Match that. An `assertRaises`
block would be stylistically foreign to every other file.

Negative cases use the try/except/else idiom, with the message naming what was
wrongly accepted:

```python
try:
    decoder.decode(malicious_payload)
except error.PyAsn1Error:
    pass
else:
    assert 0, 'Excessive continuation octets tolerated'
```

Older modules write `assert 0, '…'`; newer code writes `assert False, '…'`
(`ObjectIdentifierDecoderTestCase.testExcessiveContinuationOctets` and
`LengthFieldLimitTestCase.testOversizedLengthField`, respectively, both in
`tests/codec/ber/test_decoder.py`). Either is fine; the `else:` clause is the
part that matters, because a bare `except: pass` without it would pass even
when nothing raised.

When a specific exception type must be distinguished, add an explicit branch
rather than a broader catch. The length-limit tests assert that a
`PyAsn1Error` arrives and specifically that an `OverflowError` does not:

```python
except error.PyAsn1Error:
    pass
except OverflowError:
    assert False, 'Got OverflowError instead of PyAsn1Error'
```

Constraint violations raise `pyasn1.type.error.ValueConstraintError`, which is
a *different class* from `pyasn1.error.ValueConstraintError` and not an
instance of it. Catching `PyAsn1Error` works for both; catching
`pyasn1.error.ValueConstraintError` catches no constraint violation at all.
See [ARCHITECTURE.md](ARCHITECTURE.md) for why both exist.

## Testing a security fix

A hardening change *should* ship the five-part test set below. Existing
coverage is uneven and no single limit currently ships all five parts, so
combine the strongest examples rather than copying any one of them. The
nesting-depth limit has parts 1, 4 and 5 (`NestingDepthLimitTestCase` in
`tests/codec/ber/test_decoder.py`, with same-named mirrors in
`tests/codec/cer/test_decoder.py` and `tests/codec/der/test_decoder.py`),
but its under- and over-limit tests sit at depths 50 and 200 against a limit
of 100, not at the exact boundary parts 2 and 3 require.
`LengthFieldLimitTestCase` (`tests/codec/ber/test_decoder.py`) shows parts
1-4 with exact 8- and 9-octet boundaries, including the message assertion in
`testLengthValueAbovePlatformLimitIsRejected`, but has no mirrors. The OID
continuation-octet tests in `ObjectIdentifierDecoderTestCase` (same file)
predate the template and show parts 1-3 with exact 20- and 21-octet
boundaries, inside a type-named rather than limit-named class.

The five parts:

1. **The malicious input is rejected.** Construct the substrate by hand as a
   `bytes` literal with a comment explaining the encoding, and assert
   `PyAsn1Error` via the try/except/else idiom.
2. **Input exactly at the limit still decodes.** This is what proves the limit
   did not break legitimate data.
3. **One over the limit is rejected.** The explicit boundary case.
4. **The error message carries the limit.** Assert on message content, e.g.
   `assert 'maximum readable size' in str(exc).lower()`, so the diagnostic
   stays useful. Check the actual wording in the raise site rather than
   guessing.
5. **Mirror the rejection tests into `tests/codec/cer/test_decoder.py` and
   `tests/codec/der/test_decoder.py`.** CER and DER inherit the limit through
   module import rather than reimplementing it, but the mirrors are what stop
   a future refactor from silently exempting one codec.

Steps 1-3 belong in one `TestCase` class named after the limit, for example
`NestingDepthLimitTestCase` or `LengthFieldLimitTestCase`.

## Special patterns

**Monkeypatching interpreter globals.** `decoder.sys` *is* the real `sys`
module, so the platform-limit tests mutate it globally to exercise a branch
unreachable on a 64-bit machine. The `finally` restore is mandatory and the
pattern is not safe under parallel test execution
(`LengthFieldLimitTestCase.testLengthValueAbovePlatformLimitIsRejected` in
`tests/codec/ber/test_decoder.py`):

```python
originalMaxsize = decoder.sys.maxsize
decoder.sys.maxsize = 0x7fffffff
try:
    ...
finally:
    decoder.sys.maxsize = originalMaxsize
```

**Cross-codec behavioral regressions.** When a bug affects every codec, test
it once against all of them rather than copying a case into four files.
`tests/codec/test_encoder_no_mutation.py` is the model: it declares a `codecs`
tuple of five entry points (`ber` in both definite and indefinite mode, `cer`,
`der`, `native`) atop `DefaultedComponentsNoMutationTestCase`, then drives
every case through `itertools.product`. Its `_snapshot` helper captures
component state using `getComponentByName(name, instantiate=False)`. The
`instantiate=False` is essential, because the default would itself materialize
the absent component the test is trying to prove untouched.

**`self.subTest`** appears only in that newest module. It is fine to use in
new cross-product tests and unnecessary elsewhere.

## Layout

`tests/` mirrors the package:

```
tests/
├── base.py                        BaseTestCase
├── __main__.py                    aggregate suite
├── test_debug.py
├── type/                          test_univ, test_char, test_tag, test_constraint,
│                                  test_namedtype, test_namedval, test_opentype, test_useful
└── codec/
    ├── test_streaming.py          stream wrappers
    ├── test_encoder_no_mutation.py  cross-codec regression
    ├── ber/  cer/  der/  native/  test_encoder.py + test_decoder.py each
```

Every directory carries both `__init__.py` and `__main__.py`. Cross-codec
tests live at the `tests/codec/` level rather than inside one codec's
directory. `tests/compat/` was removed in commit `0cf7578` when the compat
shims went away; a stale `__pycache__` may still exist on disk and can be
ignored.
