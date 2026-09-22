# Security policy

app_attest decides whether a request comes from a genuine, unmodified instance of an iOS app, so a flaw in its certificate-chain, App ID hash or Counter checks lets forged or replayed requests through. Please keep security reports confidential until a fix or mitigation can be coordinated.

## Reporting a vulnerability

Use GitHub's **[Report a vulnerability](https://github.com/64x-lunicorn/app_attest/security/advisories/new)** form for a private report to the repository maintainers.

**Do not disclose vulnerabilities in public issues or pull requests.** If you cannot access the private form, open a public issue asking only for a private contact channel. Do not include vulnerability details there.

Include in the private report:

- The affected version or commit.
- A description of the impact and prerequisites.
- Minimal reproduction steps using synthetic data.
- A proposed mitigation or fix, if available.

Never include real passwords, access tokens, SSH private keys or personal data.

## Maintenance scope

app_attest is an early-stage, single-maintainer project. Fixes are developed against the current `main` branch; there is no long-term-support or backport policy. This project does not offer a guaranteed security response time.
