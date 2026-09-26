# Security Policy

## Scope and intended use
ROOTLINE is a **defensive, observe-only** research and education tool. Use the eBPF probe only on systems you own or are explicitly authorized to monitor. The synthetic attack generator emits *event records*; it does not execute anything, contact any network, or contain exploit code.

## Reporting a vulnerability
Please open a private security advisory on the repository, or email the maintainer, rather than filing a public issue. Include reproduction steps and affected versions. You should get an acknowledgement within 7 days.

## Hardening notes
- Treat all ingested records as untrusted. They pass through `rootline.normalize`, which validates and bounds every field.
- Ship the hash-chain head (`rootline verify`) off-host if you rely on it for tamper evidence.
- The runtime has no third-party dependencies. The only dev dependency is pytest.
