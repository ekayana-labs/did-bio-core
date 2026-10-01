# Security Policy

## Reporting security problems

Do not open a GitHub issue to report a security problem.

Please use the
[Report a Vulnerability](https://github.com/ekayana-labs/did-bio-core/security/advisories/new)
link with a helpful title and a detailed description of the problem.
Expect a response typically within 72 hours.

If you receive no response in the advisory, email <suraj410401@gmail.com>
with the advisory URL. Keep exploit details in the advisory and out of the
email.

## Scope

The scope is anything that makes this crate resolve a `did:bio` DID to a
document its registry state does not justify. That includes accepting a
malformed identifier, decoding account bytes to the wrong state, falling
back to the generative document when it must not, and verifying a
signature that should fail. A panic on untrusted input is in scope too,
whether the input is an identifier, account data, a key or a signature.

The on-chain registry program and the resolver CLI live in separate
repositories. Reports about them are still welcome through this channel.
