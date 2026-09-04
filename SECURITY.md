# Security Policy

## Reporting security problems

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Please use the
[Report a Vulnerability](https://github.com/ekayana-labs/did-bio-core/security/advisories/new)
link with a helpful title and a detailed description of the problem.
Expect a response typically within 72 hours.

If you receive no response in the advisory, email <suraj410401@gmail.com>
with the advisory URL. Do not put exploit details in the email; keep them
in the advisory.

## Scope

Anything that makes this crate resolve a `did:bio` DID to a document its
registry state does not justify: accepting a malformed identifier, decoding
account bytes to the wrong state, falling back to the generative document
when it must not, or verifying a signature that should fail. Panics on
untrusted input (identifiers, account data, keys, signatures) are also in
scope.

The on-chain registry program and the resolver CLI live in separate
repositories; reports about them are still welcome through this channel.
