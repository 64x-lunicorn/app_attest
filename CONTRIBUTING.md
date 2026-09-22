# Contributing to app_attest

Bug reports, clearer documentation and focused changes are welcome.

## Before you start

- Search [existing issues](https://github.com/64x-lunicorn/app_attest/issues) before opening a new one, and discuss larger changes in an issue before starting a pull request.
- Read the [project overview](README.md) and [CLAUDE.md](CLAUDE.md).
- Keep discussions respectful, constructive and focused on the work.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Development setup

Prerequisites: Elixir 1.20 and Erlang/OTP 29.

```bash
git clone https://github.com/64x-lunicorn/app_attest.git
cd app_attest
git switch -c <your-branch>
mix deps.get
```

## Checks

Before pushing, run the whole gate in one command:

```bash
mix ci
```

It runs every check CI runs: Format, Unused deps, Compile, Test. On a pull request, CI also runs Workflow lint and Secret scan and ends in `CI gate`, the only required status check. [docs/ci-cd.md](docs/ci-cd.md) describes the gate and the rules on `main`.

## Submitting a pull request

1. Keep the change focused and avoid unrelated formatting or refactors.
2. Explain the problem and the solution, and link the issue.
3. Add or update tests for changed behaviour, and update the affected documentation.
4. Write commits as Conventional Commits in English imperative mood.
5. List the checks you ran and any known limitations.

Only contribute material you have the right to submit. Contributions are made under the existing [Apache License 2.0](LICENSE).
