---
name: security-fix
description: Implement, test, and ship a pyasn1 security fix following the repository's CVE hardening conventions. Use for any vulnerability report, GHSA advisory, CVE, denial-of-service or resource-exhaustion issue, decoder limit change, downstream or RHEL backport on the 0.3.7 branch, or when generating standalone security-advisory patches.
---

# Shipping a security fix

pyasn1 is a parsing library that runs on untrusted input in TLS, LDAP and
certificate stacks, so nearly every vulnerability here is a resource-exhaustion
or crash bug in the BER decoder reached through attacker-controlled bytes. The
repository has a well-established shape for these fixes. Follow it.

Before writing code, read the security hardening section of
[docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md), which inventories the
existing limits and the recurring defect classes with their case studies.

## 0. Confirm it qualifies, then keep it private

[SECURITY.md](../../../SECURITY.md) is the canonical statement of what counts as
a vulnerability in this project. Apply it before treating anything as one:

- **Qualifies** (private advisory, normally a CVE): CPU, memory or stack
  consumption disproportionate to input size; an interpreter crash; a bypass of
  the documented `MAX_*` limits; malformed input silently decoding to a wrong
  value.
- **Does not qualify** (ordinary public fix; use the
  [issue-pr-triage](../issue-pr-triage/SKILL.md) skill instead): an exception on
  malformed input; the wrong exception type *unless* disproportionate work
  happens before it; resource use linear in input size; anything requiring a
  hostile schema; the documented CER/DER strictness gaps; timing variation.

If a genuinely exploitable report arrived as a public issue, say so and stop:
`SECURITY.md` directs reporters to a private GitHub security advisory. Do not
post reproducers, patches or analysis in a public thread before the advisory
exists.

## 1. Check whether it is already fixed

Several reports duplicate existing mitigations or describe something already
fixed but not yet released.

- Read the `MAX_*` constants at the top of `pyasn1/codec/ber/decoder.py`.
- Search `CHANGES.rst` for the defect class and for existing CVE identifiers.
- Check the pending `released XX-XX-` block at the top of `CHANGES.rst`: a fix
  may be on `main` but unreleased, which is why a reporter testing the latest
  PyPI release still reproduces it.

Reproduce against `main` and against the latest release before concluding
anything.

## 2. Write the fix in the established shape

A hardening fix in the decoder consists of five things:

1. **A named module-level constant** at the top of
   `pyasn1/codec/ber/decoder.py`, alongside the existing limits, with a comment
   explaining what the number defends against and why that value. Follow the
   naming already there: `MAX_TAG_OCTETS`, `MAX_NESTING_DEPTH`,
   `MAX_LENGTH_OCTETS`, `MAX_OID_ARC_CONTINUATION_OCTETS`.
2. **A rejection that raises `error.PyAsn1Error`**, never a bare builtin
   exception. Callers catch `PyAsn1Error`; an `OverflowError` or `MemoryError`
   escaping the decoder is itself the bug. Interpolate the limit into the
   message so the diagnostic is actionable.
3. **Enforcement inside the loop**, with an explicit counter rather than a
   post-hoc check on an already-materialized value. The point is to stop
   before the expensive thing happens.
4. **Tests**, per step 3 below.
5. **A documentation update.** Add the limit to the security-hardening
   inventory in [docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) (the
   table row plus, for a new defect class, a guardrail bullet) and keep the
   decoder-limits invariant in `AGENTS.md` accurate if the constant set
   changes. Cite code by symbol (class, method or constant) or a short
   greppable expression, never by line number: line numbers rot with every
   edit, and these documents serve human readers as much as agents.

Two structural facts should stay in view while editing. CER and DER inherit
these limits by importing the BER decoder module, and there is no per-codec
override hook: one constant protects all three codecs, and weakening it weakens
all three. The sharing goes beyond the constants, too. Most payload-decoder
instances are literally shared between BER, CER and DER through a shallow
`.copy()` of the dispatch tables at import time, so changing a BER payload
decoder changes DER, which is what signature verification depends on.

### Defect-class guardrails

Every one of these has already caused a CVE in this codebase. Check your fix
does not reintroduce one, and check the surrounding code while you are there:

- **No quadratic accumulation.** In any loop over attacker-controlled octets,
  accumulate into a `list` and convert once at the end. Never `result += (x,)`
  on a tuple: that reallocates on every arc and turns a large OID into a denial
  of service.
- **No unbounded loops over the substrate.** Any `while` loop consuming octets
  needs an explicit counter checked against a limit.
- **No unbounded integer materialization.** Do not evaluate `pow(base, exp)`,
  `10 ** n` or `x << n` where the exponent comes from the input. Use
  `math.ldexp` for base 2 and range-check base-10 exponents against
  `sys.float_info.max_10_exp`. Use floor division, not true division, when
  normalizing integer mantissas.
- **No plain `str()` of a possibly-huge integer.** Python 3.11+ raises
  `ValueError` past `sys.get_int_max_str_digits()`, so a repr or error message
  built from a tag ID or arc value must go through a hex fallback. `_tagIdToStr`
  in `pyasn1/type/tag.py` is the existing helper.
- **Forward the options dictionary.** Recursion depth rides in
  `options['_nestingLevel']`. Any code path that builds a fresh options dict
  instead of passing the existing one through resets the counter and defeats
  the nesting-depth mitigation entirely.

## 3. Tests

Use the five-part template in
[docs/TESTING.md](../../../docs/TESTING.md#testing-a-security-fix): the
malicious substrate is rejected, input exactly at the limit still decodes, one
over the limit is rejected, the error message is asserted, and the rejection
tests are mirrored into `tests/codec/cer/test_decoder.py` and
`tests/codec/der/test_decoder.py`.

The at-the-limit test is not optional padding. It is the only thing that
distinguishes a fix from a regression that breaks legitimate data.

Verify with the CI form, since a new `warnings.warn` or an unexpected
`DeprecationWarning` is fatal:

```bash
python -Werror -m unittest discover -s tests
```

## 4. Land it

Fixes for embargoed advisories are developed in the private fork GitHub creates
for a security advisory and merged from there. The resulting merge commit
carries GitHub's default subject, literally `Merge commit from fork`, usually
with no body; this is expected, not sloppiness.

CVE and GHSA identifiers do not appear in the code or the merge commit. They
are added to `CHANGES.rst` at release time. The entry format is:

```
- CVE-YYYY-NNNNN (GHSA-xxxx-xxxx-xxxx): <what was fixed and how> (thanks
  for reporting, <handle>)
```

Put the reporter credit at the end of the bullet. The shipped 0.6.4 entry has
one inserted mid-sentence, splitting the description in half; do not copy that.

## 5. Standalone advisory patches

`security-advisory-patches/` holds one `git format-patch` file per advisory, so
each fix can be handed to a distributor independently. These are untracked
working artifacts (`.gitignore` excludes `*.patch`) passed to distributors out
of band, not committed.

Generate them one advisory at a time, each rebased onto the base it is meant to
apply to; their bases intentionally differ. Regenerating the directory as a
single `format-patch` series would renumber them into a dependent chain and
silently change which trees they apply to.

## 6. Downstream backports

There is a long-lived `0.3.7` branch carrying backports for distributions
shipping that ancient release (Red Hat's packaging, among others).

Port the fix; do not cherry-pick it. The 0.3.7 API predates the 0.4 rewrite:
simple types derive from `base.AbstractSimpleAsn1Item` rather than
`SimpleAsn1Type`, and octet handling goes through the removed
`pyasn1.compat.octets` helpers (`ints2octs`, `str2octs`, `null`). A cherry-pick
will either conflict or, worse, apply cleanly into code that no longer means the
same thing.

Export the result as an RPM-ready patch named for the release and identifier,
in the style of the existing `python-pyasn1-0.3.7-CVE-2026-59886.patch`.

Run the branch's own tests after backporting; the old suite predates several
conventions used on `main`.
