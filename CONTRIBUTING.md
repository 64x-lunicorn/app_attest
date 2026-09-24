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

### Optional: Apple's real risk-metric endpoint

Most of the suite needs nothing but Elixir. Two tests
(`test/app_attest/risk_metric_apple_test.exs`) are the exception: they send a
real request to Apple's development risk-metric endpoint, because only Apple
can say whether the DeviceCheck JWT this library builds is one it accepts.
They are excluded unless the credentials below are set, so `mix test` is green
on a fresh clone without an Apple Developer account.

To run them, create a DeviceCheck key in the Apple Developer portal
(Certificates, Identifiers & Profiles > Keys, with DeviceCheck enabled),
download its `.p8` file, and keep it outside this repository:

```bash
mkdir -p ~/.config/app_attest
mv ~/Downloads/AuthKey_XXXXXXXXXX.p8 ~/.config/app_attest/
chmod 600 ~/.config/app_attest/AuthKey_XXXXXXXXXX.p8

export APPLE_DEVICECHECK_KEY_FILE=~/.config/app_attest/AuthKey_XXXXXXXXXX.p8
export APPLE_DEVICECHECK_KEY_ID=XXXXXXXXXX   # the Key ID Apple assigned
export APPLE_TEAM_ID=YYYYYYYYYY              # your Apple Developer Team ID
```

Never commit the `.p8` file or paste its contents anywhere. In CI the same
tests read the key's *contents* from the `APPLE_DEVICECHECK_KEY` repository
secret, with `APPLE_DEVICECHECK_KEY_ID` and `APPLE_TEAM_ID` as repository
variables; a pull request from a fork gets no secret and simply skips them.

## Checks

Before pushing, run the whole gate in one command:

```bash
mix ci
```

It runs every check CI runs: Format, Unused deps, Compile, Test. On a pull request, CI also runs Pending scenarios (advisory), Workflow lint and Secret scan and ends in `CI gate`, the only required status check. [docs/ci-cd.md](docs/ci-cd.md) describes the gate and the rules on `main`.

## Submitting a pull request

1. Keep the change focused and avoid unrelated formatting or refactors.
2. Explain the problem and the solution, and link the issue.
3. Add or update tests for changed behaviour, and update the affected documentation.
4. Write commits as Conventional Commits in English imperative mood.
5. List the checks you ran and any known limitations.

Only contribute material you have the right to submit. Contributions are made under the existing [Apache License 2.0](LICENSE).
