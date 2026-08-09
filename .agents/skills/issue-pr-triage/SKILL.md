---
name: issue-pr-triage
description: Triage pyasn1 GitHub issues and pull requests. Use when asked to triage, review, respond to, or assess an issue or pull request, judge whether a report is a bug or a security problem, or evaluate an external contribution for merge readiness.
---

# Triaging issues and pull requests

pyasn1 is a low-level parsing library that most people encounter as a transitive
dependency, so reports arrive in two very different flavors: ordinary API
confusion, and parser bugs reachable from untrusted input. Separating those two
is the first job of triage, because they take different routes.

Repository conventions used below: labels are the GitHub defaults plus a
repo-specific `work in progress` (`bug`, `documentation`, `duplicate`,
`enhancement`, `good first issue`, `help wanted`, `invalid`, `question`,
`wontfix`, `work in progress`). Merged pull requests get
a commit subject of the form `Short description (#N)`.

## 1. Security screen, always first

Before writing any public reply, decide whether the report describes something
an attacker could trigger by feeding crafted bytes to a decoder.
[SECURITY.md](../../../SECURITY.md) is the canonical qualifies/does-not-qualify
list: apply it, don't improvise.

Signals that a report may qualify: unbounded memory growth, hangs on small
inputs, quadratic behavior, `MemoryError` or a process crash, anything where the
*cost* is disproportionate to the input size.

If it qualifies:

- Do not post a reproducer, patch or analysis in the public thread.
- Point the reporter at `SECURITY.md`, which directs them to open a private
  GitHub security advisory.
- Continue under the [security-fix](../security-fix/SKILL.md) skill.

The boundary that comes up most often: a *wrong exception type* is an ordinary
public bug, per SECURITY.md and as issues #54, #119 and #120 were handled. It
stops being ordinary when disproportionate work happens *before* the exception;
in that case the work is the vulnerability, not the raise. Judge by what happens
before the raise, not by the exception name.

## 2. Check whether it is known, or already fixed

Three places, in order:

- The pending `released XX-XX-` block at the top of `CHANGES.rst`. A fix may be
  merged but unreleased, which is exactly what a reporter testing the latest
  PyPI release would not see. This explains a large share of reports.
- `git log --oneline` and the released `CHANGES.rst` entries.
- `gh issue list --state all --search "<keywords>"` and
  `gh pr list --state all --search "<keywords>"`.

If it is already fixed on `main` but unreleased, say so explicitly and name the
commit; that is a genuinely useful answer, not a brush-off.

### Recurring theme worth recognizing

A large fraction of recent reports are the same defect class: a Python builtin
exception (`ValueError`, `IndexError`, `OverflowError`) escaping where
`PyAsn1Error` is expected, usually on truncated or malformed input. Issues #119
and #120 and pull requests #121 and #122 are all this shape.

The library's contract is that malformed input raises `PyAsn1Error` (or a
subclass), so callers can write one `except`. These are handled publicly;
SECURITY.md explicitly classes them as ordinary bugs. The fix is to catch the
builtin at the point it arises and re-raise as `PyAsn1Error` with a descriptive
message, plus a regression test. Check whether an existing issue already covers
the same call path before opening another.

## 3. Reproduce before classifying

Reproduce with the CI-equivalent invocation, on `main`:

```bash
python -Werror -c "<minimal reproducer>"
```

Reduce the reporter's example to the smallest substrate or schema that still
shows the behavior. If it does not reproduce, check the reporter's pyasn1
version before concluding anything, and check whether they are actually hitting
`pyasn1-modules` or a caller like `pyOpenSSL`.

Then classify with a default label and, where relevant, note whether it is
approachable enough for `good first issue`.

## 4. Reviewing a pull request

Most incoming pull requests are from external contributors and land as
`Short description (#N)`. Work through this checklist; the first four items are
the ones that most often need to be raised with the contributor.

**Correctness and scope**

- [ ] Does it fix the reported problem, without bundling unrelated changes?
- [ ] For a decoder change: does it preserve the exception contract that
      malformed input raises `PyAsn1Error`, never a bare builtin?

**Cross-codec impact**: the one reviewers miss

- [ ] Does it touch `pyasn1/codec/ber/`? If so it almost certainly changes CER
      and DER too, because they derive their dispatch tables from BER with a
      shallow copy at import time and share most payload-codec instances. See
      the codec family section of
      [docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md).
- [ ] Are there mirrored tests under `tests/codec/cer/` and `tests/codec/der/`
      when rejection behavior changed?
- [ ] If it registers a new type, is it added to the BER maps (which CER and DER
      inherit at import) rather than duplicated into `cer/` and `der/`? A derived
      `TAG_MAP` keyed by `univ.Set.tagSet` or `univ.Sequence.tagSet` silently
      clobbers the inherited `SetOf`/`SequenceOf` entry.

**CI survival**

- [ ] Any new `warnings.warn(...)` in `pyasn1/`? The suite runs under `-Werror`,
      so an unguarded warning fails every test that reaches it. This is exactly
      why pull request #94 (`Fix broken BitString`, matejcik) cannot be merged
      as-is: it introduces a `warnings.warn` in `BitString` initialization.
- [ ] Python 3.8 compatible syntax only: `requires-python` is `>=3.8`.
- [ ] No new runtime dependency. pyasn1 has none, deliberately.

**Tests and conventions**

- [ ] Tests present, following [docs/TESTING.md](../../../docs/TESTING.md):
      `BaseTestCase` subclass, bare `assert`, try/except/else for negative cases.
- [ ] A new test module is registered in the parent `tests/**/__main__.py`,
      otherwise `python -m tests` silently skips it.
- [ ] Import style matches the specific module edited (it varies per file, not per
      directory).
- [ ] If the change alters behavior documented in `AGENTS.md`, `docs/` or a
      skill, or renames a symbol those documents cite, the same PR updates the
      affected document. Doc references are symbols (file plus class, method
      or constant, or a greppable expression), never line numbers, which rot
      with every edit; the docs serve human readers as much as agents.

**API compatibility**

- [ ] Does it delete something that merely *looks* dead? The compatibility
      surface section of [ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) lists
      the shims, aliases and legacy code paths that must survive. A tidy-up pull
      request that removes them is a breaking change for downstream users and
      should be declined with that explanation.
- [ ] Does it "fix" a documented intentional wart? The known-warts section lists
      them, including the `isSuperTypeOf` precedence quirk that is observable to
      external callers passing `matchTags=False`, and the two distinct
      `ValueConstraintError` classes.

**Changelog**

- [ ] An entry added to the pending `released XX-XX-` block at the top of
      `CHANGES.rst`, referencing the pull request. Remember the file is compiled
      into the Sphinx `-W` build, so malformed reST there fails CI.

## 5. Verify locally before approving

```bash
gh pr checkout <N>
python -Werror -m unittest discover -s tests
```

Add `tox -e docs` if the branch touches any `.rst`, `CHANGES.rst` or `docs/`
content. See [pre-commit-check](../pre-commit-check/SKILL.md) for the full gate
matrix.

## 6. Responding

Be concrete and cite evidence: file and symbol (or a permalink pinned to a
commit), or the commit that already fixed it. When declining, explain the
invariant that makes the change unsafe rather than just saying no; most of these
pull requests are well-intentioned changes that happen to collide with something
non-obvious, and the explanation is the valuable part.

Credit reporters and contributors in the `CHANGES.rst` entry, with the credit at
the end of the bullet.
