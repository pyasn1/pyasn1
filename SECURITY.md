# Security Policy

## Supported Versions

Security updates are applied only to the latest release.

## What qualifies as a vulnerability

pyasn1 is a parsing library routinely fed attacker-controlled bytes (TLS, LDAP
and certificate stacks), so the line between an ordinary bug and a
vulnerability is drawn around what crafted *input* can extract from the
process.

**Qualifies (report privately as described below):**

- CPU, memory or stack consumption disproportionate to the size of the input
  (quadratic accumulation, unbounded integer materialization, unbounded
  recursion or nesting)
- An interpreter crash or abort on any input
- A bypass of the decoder's documented limits (the `MAX_*` constants in
  `pyasn1/codec/ber/decoder.py`)
- Malformed input silently decoding to a wrong value instead of raising

**Does not qualify (open an ordinary public issue):**

- An exception raised on malformed input: rejecting bad input is the decoder's
  contract, not a defect
- The wrong exception type, meaning a Python builtin such as `ValueError`,
  `IndexError` or `OverflowError` escaping where `PyAsn1Error` is documented,
  *unless* disproportionate work happens before the exception is raised, in
  which case that work is the vulnerability
- Resource use proportional (roughly linear) to input size
- Anything that requires a hostile ASN.1 *schema*: schemas are trusted code
  supplied by the application, not attacker input
- The documented CER/DER strictness gaps on the schema-driven decoding path
- Timing variation: pyasn1 makes no constant-time guarantees

The inventory of current decoder limits and past CVEs is kept in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-hardening-inventory).

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please
report it privately. **Do not disclose it as a public issue.** This gives us
time to work with you to fix the issue before public exposure, reducing the
chance that the exploit will be used before a patch is released.

Please disclose it at our
[security advisory](https://github.com/pyasn1/pyasn1/security/advisories/new).

This project is maintained by a team of volunteers on a reasonable-effort
basis. As such, vulnerabilities will be disclosed on a best-effort basis.
