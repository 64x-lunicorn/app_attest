<div align="center">

# app_attest

<img src="docs/assets/app_attest-banner.svg" alt="app_attest - Apple App Attest validation for Elixir servers" width="1200">

### Apple App Attest validation for Elixir servers.

Elixir library validating Apple's App Attest attestations and assertions, built for Corridor's own server.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-22c55e?style=flat-square)](LICENSE)
[![Built with Elixir](https://img.shields.io/badge/built_with-Elixir-6e4a7e?style=flat-square)](mix.exs)

[How it works](#how-it-works) &nbsp; / &nbsp;
[Quickstart](#quickstart) &nbsp; / &nbsp;
[Where the design lives](#where-the-design-lives) &nbsp; / &nbsp;
[Contributing](CONTRIBUTING.md) &nbsp; / &nbsp;
[Report a bug](https://github.com/64x-lunicorn/app_attest/issues)

</div>

---

## Trust the device, not the request.

app_attest checks that the requests reaching your server come from a genuine, unmodified instance of your iOS app. It validates attestations against Apple's App Attest root certificate, including the certificate chain, nonce, App ID hash and Key ID, and validates assertions against the public key and Counter you stored for that device, so a replayed assertion is rejected. It also fetches Apple's per-device risk metric. The library keeps no state of its own: you pass in what you stored earlier and get back what to store next.

**Apple's checks, done right once, so you don't hand-write them.**

| | What you get |
| :--- | :--- |
| **Attestation validation** | Checks the certificate chain against Apple's App Attest root, the nonce, the App ID hash and the Key ID, and returns the Device to store: public key, start Counter, environment and Receipt. |
| **Assertion validation** | Checks the signature against the public key stored in the Device, the App ID hash and a Counter strictly greater than the stored one, so a captured Assertion cannot be replayed. |
| **Development and production kept apart** | Records the environment a device attested in and rejects Attestations and Assertions from the other one. |
| **Risk metric** | Fetches Apple's per-device Risk metric and verifies its Receipt; informational only, never a reason to accept or reject. |
| **Receipt reading** | Verifies any Receipt against Apple Root CA - G3 and reads its type, Risk metric, Not Before and expiration time. |
| **No state of its own** | You pass in what you stored and get back what changed; storage stays in your server. |

> [!NOTE]
> Implemented: every scenario of [Spec 64x-lunicorn/Corridor#166](https://github.com/64x-lunicorn/Corridor/issues/166) passes. Unpublished and private until it is proven against real devices in Corridor's first TestFlight round, then published on Hex ([research 0002](https://github.com/64x-lunicorn/Corridor/blob/main/research/0002-app-attest-elixir-library/README.md)).

## How it works

```text
iOS app --attestation--> your server --> AppAttest.Attestation.validate --> Device: public key, Counter, environment, Receipt (you store it)
iOS app --assertion----> your server --> AppAttest.Assertion.validate   --> Device with the new Counter (you store it)
                         your server --> AppAttest.RiskMetric.fetch     --> Risk metric and new Receipt (you record them)
```

Every function takes the state your server stored earlier as input and returns what changed, so storage, timing and refresh stay with the caller.

```elixir
root = AppAttest.RootCertificate.default()

# Once per key: validate the Attestation and store the Device it returns.
{:ok, device} =
  AppAttest.Attestation.validate(attestation_object, key_id, challenge, app_id, root, :production)

# Per request: validate the Assertion and store the Device with its new Counter.
{:ok, device} =
  AppAttest.Assertion.validate(assertion_object, client_data, app_id, device, :production)

# Now and then: record the Risk metric and store the new Receipt.
{:ok, %{risk_metric: risk_metric, receipt: receipt}} =
  AppAttest.RiskMetric.fetch(
    device.receipt,
    device.environment,
    device_check_key,
    AppAttest.RootCertificate.apple_root_ca_g3()
  )
```

## Quickstart

1. Clone the repository:

   ```bash
   git clone https://github.com/64x-lunicorn/app_attest.git
   ```

2. Enter it:

   ```bash
   cd app_attest
   ```

3. Fetch the dependencies:

   ```bash
   mix deps.get
   ```

4. Run every check:

   ```bash
   mix ci
   ```

## Where the design lives

Everything about *what* this library does and *why* is tracked on `64x-lunicorn/Corridor`, not here:

- [Spec #166](https://github.com/64x-lunicorn/Corridor/issues/166) — domain behaviour and acceptance criteria
- [Architecture #174](https://github.com/64x-lunicorn/Corridor/issues/174) — component design, decisions, implementation order
- [Wayfinder #175](https://github.com/64x-lunicorn/Corridor/issues/175) — the Spec's tickets and the order they were built in
- Licensed Apache-2.0 per [ADR 0008](https://github.com/64x-lunicorn/Corridor/blob/main/docs/adr/0008-the-app-attest-library-is-licensed-apache-2-0.md)

## Documentation

| Guide | Start here when you want to... |
| :--- | :--- |
| [Terms](CONTEXT.md) | Look up what Attestation, Assertion, Counter, Risk metric, Device, Key ID and Receipt mean here. |
| [CI/CD](docs/ci-cd.md) | Understand the gate, run it locally and see the rules on `main`. |
| [Contributing](CONTRIBUTING.md) | Set up development, run the checks and submit a focused change. |
| [Security policy](SECURITY.md) | Report a vulnerability privately. |

## Contributing

Bug reports and focused pull requests are welcome. Run the whole gate locally before pushing:

```bash
mix ci
```

New behaviour starts as a Spec and tickets in `64x-lunicorn/Corridor`.

Use synthetic data in examples, tests and issues. See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks and what a change needs.

## License and credits

app_attest is licensed under the **[Apache License 2.0](LICENSE)**.
The copyright notice is **Copyright (c) 2026 64x-lunicorn**.
