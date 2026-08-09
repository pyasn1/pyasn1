---
name: pre-commit-check
description: Run pyasn1's CI-equivalent verification before committing or pushing. Use when asked to verify changes, check whether CI will pass, run the tests before a commit, or immediately before creating any commit in this repository.
---

# Pre-commit check

All of pyasn1's gates live in `tox.ini`, not in the GitHub Actions workflow.
The workflow's tests job only installs tox and calls it; a separate `sdist`
job re-runs `python -m build` for release artifacts, which `tox -e build`
already covers. That means you can reproduce CI exactly on your machine, and
it also means the obvious local command
(`python -m unittest discover -s tests`, without `-Werror`) does not reproduce
it.

Work through the steps in order. Stop at the first failure and report it rather
than continuing.

## 1. Inspect what is staged, before anything else

```bash
git status --short
```

Read the output. If anything is staged that you did not deliberately stage,
unstage it; this working tree has previously accumulated scratch patches,
`.DS_Store` and lock files in the index.

Two rules follow from that history:

- Never run `git commit -a` or `git add -A` / `git add .` in this repository.
- Stage with explicit pathspecs:
  `git add pyasn1/codec/ber/decoder.py tests/codec/ber/test_decoder.py`.

## 2. Always: the test suite, in CI's form

```bash
python -Werror -m unittest discover -s tests
```

`-Werror` is set on the `commands` line of `[testenv]` in `tox.ini`. Any warning
raised anywhere during the suite is a hard failure. The suite is fast, under a
second, so there is no reason to skip it.

If you prefer the fully isolated form, `tox -e py310` runs the same command in a
clean environment.

## 3. Conditionally: the remaining gates

Run the ones your diff actually touches. `tox` is not installed in a fresh
checkout: install it (`pip install tox`) or run the underlying command directly.
Never report a gate as passing that you were unable to run; say it was skipped
and why.

| If the diff touches… | Run | Notes |
|---|---|---|
| any logic in `pyasn1/` | `tox -e cover` | coverage floor is 80% (`[testenv:cover]` in `tox.ini`) |
| any file in `pyasn1/` | `tox -e bandit` | scans `pyasn1/` only, never `tests/` |
| any `.rst`, `CHANGES.rst`, or anything under `docs/` | `tox -e docs` | Sphinx runs with `-W`; every warning fails |
| `pyproject.toml`, `MANIFEST.in`, `README.md` | `tox -e build` | `twine check --strict` validates README rendering |

Two things to know while reading those results:

`tox -e cover` does not pass `-Werror` and does not pass `-s tests`
(the `[testenv:cover]` command in `tox.ini`), so a green coverage run is not
evidence that the `-Werror` gate passes. Treat it as a coverage measurement only.

`CHANGES.rst` is pulled into the Sphinx build via
`.. include::` from `docs/source/changelog.rst`. A malformed changelog entry,
say a heading underline shorter than its title or unbalanced backticks, fails
`tox -e docs` even though the file lives at the repository root and looks like
plain text.

## 4. Codec-specific checks

If the diff touches anything under `pyasn1/codec/ber/`, you have almost certainly
changed CER and DER as well: they derive their dispatch tables from BER with a
shallow copy at import time and share most payload-codec instances. See the codec
family section of [ARCHITECTURE.md](../../../docs/ARCHITECTURE.md).

So: confirm the cer, der and native test results in the discover run above are
green, and if you added a decoder limit or changed rejection behavior, confirm
there are mirrored tests under `tests/codec/cer/` and `tests/codec/der/`.

## 5. Diff hygiene sweep

```bash
git diff --cached
```

Check for:

- **Deprecated aliases.** No reads of the module attributes `.tagMap` or
  `.typeMap` on a codec module. They raise `DeprecationWarning`, which is fatal
  under `-Werror`. Use `TAG_MAP` and `TYPE_MAP`.
- **New test modules registered.** A new `test_*.py` must also be added to the
  `suite` list in its parent `tests/**/__main__.py`, or `python -m tests` will
  silently never run it. See [TESTING.md](../../../docs/TESTING.md).
- **New warnings.** Any `warnings.warn(...)` added to `pyasn1/` will fail the
  suite under `-Werror` unless every test path that reaches it explicitly
  expects the warning.
- **Python 3.8 compatibility.** `requires-python` is `>=3.8`, so no `match`
  statements, no `X | Y` type unions, no builtin generics in annotations.
- **Changelog entry.** A user-visible behavior change needs a bullet under the
  pending `released XX-XX-` block atop `CHANGES.rst`, and that file is reST
  compiled under `-W`, so run `tox -e docs` after editing it (see step 3).
- **Docs still true.** If the diff changes behavior, limits, error messages or
  conventions described in `AGENTS.md`, `docs/ARCHITECTURE.md`,
  `docs/TESTING.md` or a skill, or renames a symbol they cite, update the
  affected document in the same commit. The docs reference code by symbol name,
  so a rename orphans them silently.

  When updating a document, keep its citation style: references are symbols,
  not line numbers. Cite code by file plus class, method or constant, or by a
  short distinctive expression to grep for. Line numbers are deliberately
  absent: they rot with every edit, and these documents serve human readers as
  much as agents. If a cited symbol is missing, the code has moved or changed;
  re-verify the claim rather than deleting the reference.

## 6. Confirm the push target before pushing

This clone has more than one remote and they have diverged in the past; release
tags have pointed at different commits than the local branch of the same name.
Check `git remote -v` and `git log --oneline origin/main -1` against
`upstream/main` before pushing anything.
