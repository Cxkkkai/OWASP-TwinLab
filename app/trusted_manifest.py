"""Fixed trust input for the A03 synthetic supply-chain experiment.

The expected digest is deliberately stored outside the resolver module.  The
resolver computes the digest of repository bytes at runtime and compares it
with this reviewed lab manifest value.
"""

TRUSTED_A03_MANIFEST = {
    "package": "acme-widget",
    "version": "2.4.1",
    "sha256": "707baa20045850e0172941e770798e60088834da930b3ef522da2476acc9fcde",
}
