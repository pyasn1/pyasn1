# AGENTS.md

Canonical agent context. `CLAUDE.md` is a symlink to this file; edit only
`AGENTS.md`. pyasn1 implements ASN.1 types (ITU-T X.680) and BER/CER/DER
codecs (ITU-T X.690) in pure Python: zero runtime dependencies, Python 3.8+
including PyPy, packaged from `pyproject.toml`, version single-sourced at
`pyasn1/__init__.py`.

## Where things are documented

| Topic | Document |
|---|---|
| Subsystem deep-dives, diagrams, invariant rationale | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Security limits, CVE inventory, defect classes | [§ Security hardening inventory](docs/ARCHITECTURE.md#security-hardening-inventory) |
| What is (and is not) a security vulnerability; reporting | [SECURITY.md](SECURITY.md) |
| API that looks removable but is not; oddities not to "fix" | [§ Compatibility surface](docs/ARCHITECTURE.md#compatibility-surface-looks-dead-is-not), [§ Known warts](docs/ARCHITECTURE.md#known-warts-intentional) |
| Test conventions, gates, security-test template | [docs/TESTING.md](docs/TESTING.md) |
| Changelog (reST, compiled into the `-W` Sphinx build) | `CHANGES.rst` |
| Task procedures | `.agents/skills/`: `issue-pr-triage`, `security-fix`, `pre-commit-check`, `add-test` |

`docs/*.md` and root `*.md` sit deliberately outside the Sphinx source tree
(`docs/source/`, `.rst` only). Do not move them there, since Markdown is
silently ignored, and do not convert them to `.rst`: an `.rst` missing from a
toctree fails the `-W` build.

These documents are read by humans as well as agents, and they are part of the
change surface. A diff that alters behavior, limits, error messages,
conventions or invariants they describe, or renames a symbol they cite,
updates the affected document in the same commit. References are by symbol
(file plus class, method or constant) or a short greppable expression, never
by line number: line numbers rot with every edit. If a cited symbol is
missing, the code has moved or changed; re-verify the claim and update the
document in the same change.

## Commands

```bash
# The suite as CI runs it. -Werror lives in tox.ini, not the workflow, so a plain
# `python -m unittest` passes on changes that fail CI.
python -Werror -m unittest discover -s tests
python -m unittest tests.type.test_univ   # one module

tox -e py310     # same suite, isolated env
tox -e cover     # coverage floor 80% -- runs WITHOUT -Werror and without -s tests
tox -e bandit    # scans pyasn1/ only, never tests/
tox -e docs      # Sphinx -W: every warning is an error
tox -e build     # build + twine check --strict (validates README rendering)
```

`tox` is not installed in a fresh checkout: install it or run the gate
directly, and never report a gate green that you did not run. Before
committing, use the `pre-commit-check` skill, which sequences these with their
skip conditions.

## Repository map

Layout mirrors expectations (`tests/` mirrors the package, `docs/source/` is
Sphinx `.rst` only); full module map in ARCHITECTURE.md. The parts people get
wrong: `type/univ.py` holds the universal types looked for elsewhere,
`ObjectIdentifier` and `Real` included, while `type/useful.py` is only
`ObjectDescriptor` plus the time types and character strings live in
`type/char.py`; `type/base.py` has the spine `Asn1Item` → `Asn1Type` →
`{SimpleAsn1Type, ConstructedAsn1Type}`; `type/error.py` holds a *second*
`ValueConstraintError`; and `codec/streaming.py` is the resumable-stream
engine the BER/CER/DER family runs on (the native codec does not use it).

## Critical invariants

Most map to a CVE or a shipped regression; the rest are frozen warts that
downstream callers depend on. Rationale in
[ARCHITECTURE.md](docs/ARCHITECTURE.md).

- **Editing BER edits DER.** DER imports CER imports BER, and each derived
  codec copies the parent's `TAG_MAP`/`TYPE_MAP` *shallowly* at import: 22 of
  26 payload-decoder and 22 of 27 payload-encoder `TAG_MAP` instances are the
  same objects in all three codecs, and the derived *decoder* `TYPE_MAP`s are
  inherited wholesale. Editing a BER payload codec, or setting an attribute on
  one of those instances, changes DER, which signature verification depends
  on. Conversely, registering a new type in the BER source is enough; only
  *runtime* mutation after import fails to propagate. Add to `cer/` or `der/`
  only when that codec needs different behavior.
- **CER/DER decoder strictness does not fire on the schema-driven path**,
  because the fully inherited `TYPE_MAP` is consulted before `TAG_MAP`
  whenever an `asn1Spec` is supplied. DER's `supportConstructedForm=False` and
  CER's canonical Boolean check are inert there; only
  `supportIndefLength=False` is unconditional. Test strictness changes both
  with and without a schema.
- **Do not weaken the decoder limits.** `MAX_OID_ARC_CONTINUATION_OCTETS`,
  `MAX_TAG_OCTETS`, `MAX_NESTING_DEPTH` and `MAX_LENGTH_OCTETS` sit at the top
  of `pyasn1/codec/ber/decoder.py`; the unnamed `length > sys.maxsize` guard
  is enforced inline in the `stDecodeLength` state handling of
  `SingleItemDecoder.__call__`. There is no per-codec override hook: one
  constant protects all three codecs.
- **`eoo.endOfOctets` is compared with `is`, never `==`.** It is a singleton
  whose `defaultValue` is `0`, so `==` is true against a decoded `Integer(0)`
  and would truncate an indefinite-length container silently, with no
  exception.
- **Forward the options dict.** Recursion depth rides in
  `options['_nestingLevel']`, not the call stack; a freshly built options dict
  defeats the nesting-depth fix.
- **The streaming idiom is load-bearing.** Reads are written as `for chunk in
  readFromStream(...): if isinstance(chunk, SubstrateUnderrunError): yield chunk`
  then use the leaked loop variable. Rewriting it as `next()` or a
  comprehension breaks resumable decoding of partial input. Decoders are
  generators throughout; turning a `yield` into a `return` breaks the
  pipeline.
- **`typeId` comes from a global counter at class-definition time.**
  Reordering classes renumbers everything after them, which is safe in-process
  (the maps are built from `univ.X.typeId` at import) but not across versions
  or pickles. What does corrupt dispatch is a *duplicate* `typeId`: a subclass
  that omits its own `typeId = ...getTypeId()` line inherits its parent's and
  silently steals its slot.
- **Never read the deprecated `tagMap`/`typeMap` module attributes**: they
  raise `DeprecationWarning`, fatal under `-Werror`. Use `TAG_MAP`/`TYPE_MAP`.
- **`isSuperTypeOf`'s missing parentheses matter to callers**, not to the
  decoder: `matchTags=False` short-circuits the check to `True`. The decoder
  also passes `verifyConstraints=False`, where both readings agree, so
  "fixing" the precedence is a narrow API break rather than a repo-wide decode
  change, but still a break.
- **Two `ValueConstraintError` classes exist.** Violations raise the one in
  `pyasn1.type.error`, which is *not* an instance of
  `pyasn1.error.ValueConstraintError`. Only `except PyAsn1Error` catches both.
- **Encoders must not mutate what they encode:** iterate with
  `getComponentByPosition(idx, instantiate=False)` and branch on `noValue`,
  never materializing an absent DEFAULT/OPTIONAL component. Pinned by
  `tests/codec/test_encoder_no_mutation.py`.
- **Decoder code reads `asn1Object.componentType`, never
  `asn1Spec.componentType`**, so recursive schemas completed after
  instantiation still resolve. Encoders deliberately still read
  `asn1Spec.componentType`; do not "fix" them to match.
- **Denial-of-service guardrails on attacker-controlled input:** accumulate
  into a list and convert once (never `tuple += (x,)`); never evaluate
  `pow`/`**`/`<<` with an *unbounded* input-derived exponent, bounding it
  first the way `Real.__float__` does; route `str()` of a possibly-huge
  integer through a hex fallback, since Python 3.11+ raises past
  `sys.get_int_max_str_digits()`.
- **`subtype()` *accumulates* every keyword; `clone()` *replaces*.** That is
  right for `subtypeSpec` and wrong for everything else:
  `OctetString('abc').subtype(encoding='utf-8').encoding` is the string
  `'iso-8859-1utf-8'`. Use `clone()` for non-constraint attributes.
  No-argument `clone()`/`subtype()` on a simple type returns `self`;
  constructed types always copy. Unknown encode/decode keyword arguments are
  silently swallowed, so a misspelled option is a no-op.

## Coding rules

- Python 3.8-compatible syntax only: no `match`, no `X | Y` unions, no builtin
  generics.
- Never add a runtime dependency.
- No linter, formatter or `CONTRIBUTING.md` exists: match the surrounding
  file's style exactly, including its import spelling, which varies per file
  rather than per directory. New files carry the six-line copyright header
  used throughout the tree.
- Changelog entries go under the pending `released XX-XX-` block atop
  `CHANGES.rst`; dates are day-first (`08-07-2026` is 8 July 2026) and each
  heading underline must be at least as long as its title.

## Testing

Subclass `tests.base.BaseTestCase`: its `setUp` enables every debug flag with
a no-op printer, so the suite executes every `if LOG:` branch with output
discarded and a broken logging format string is a test failure. If you
override `setUp`, call `BaseTestCase.setUp(self)` first. Use bare `assert`;
there is no `assertRaises` and no pytest. Negative cases use `try: ... except
PyAsn1Error: pass else: assert 0, '... tolerated'`. A new test module must
also be registered in the parent `tests/**/__main__.py`, or `python -m tests`
silently never runs it. Full conventions and the five-part security-test
template: [docs/TESTING.md](docs/TESTING.md).

## Git and workspace hazards

- **Never `git commit -a` or `git add -A`.** Stage explicit pathspecs and read
  `git status --short` first; this tree has collected scratch patches before.
- **Scope searches to `pyasn1/`, `tests/`, `docs/`**: a stale copy of the
  package can sit under `build/lib/` beside a local `.venv/`, so repo-wide
  grep returns phantom matches with wrong line numbers.
- **Branch `0.3.7` is the downstream backport line** on the pre-0.4 API: never
  merge it toward `main`, and port fixes onto it rather than cherry-picking.
- **Confirm the push target**: this clone has diverging remotes, and release
  tags have pointed at different commits than the local branch of the same
  name.

## Releasing

Bump `__version__` in `pyasn1/__init__.py` and nowhere else; `pyproject.toml`
and `docs/source/conf.py` read it dynamically. Date the shipping section of
`CHANGES.rst` as `Revision X.Y.Z, released DD-MM-YYYY`, newest first; to ship
security-only, rename the pending block to the next minor and insert a fresh
dated block beneath it. Commit exactly those two files with subject
`Prepare release X.Y.Z`, tag annotated `vX.Y.Z` with message `Release X.Y.Z`,
then dispatch `.github/workflows/pypi.yml` manually, TestPyPI first. Run
`tox -e docs` before tagging: `CHANGES.rst` is compiled into the Sphinx build,
so malformed reST there fails CI.
