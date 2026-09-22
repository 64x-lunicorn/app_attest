# app_attest

Elixir library validating Apple's App Attest attestations and assertions: certificate chain, nonce, App ID hash and replay-safe counter checks, plus Apple's per-device risk metric. Built for [Corridor](https://github.com/64x-lunicorn/Corridor)'s own server, published as a standalone library once proven against real devices.

Private until published on Hex after Corridor's first TestFlight round ([research 0002](https://github.com/64x-lunicorn/Corridor/research/0002-app-attest-elixir-library/README.md)).

## Where the design lives

This repository is greenfield — everything about *what* to build and *why* is tracked on `64x-lunicorn/Corridor`, not here:

- [Spec #166](https://github.com/64x-lunicorn/Corridor/issues/166) — domain behaviour and acceptance criteria
- [Architecture #174](https://github.com/64x-lunicorn/Corridor/issues/174) — component design, decisions, implementation order
- Tickets, in build order: [#172](https://github.com/64x-lunicorn/Corridor/issues/172) (integration tests) → [#168](https://github.com/64x-lunicorn/Corridor/issues/168) → [#169](https://github.com/64x-lunicorn/Corridor/issues/169) → [#170](https://github.com/64x-lunicorn/Corridor/issues/170) → [#171](https://github.com/64x-lunicorn/Corridor/issues/171)
- Licensed Apache-2.0 per [ADR 0008](https://github.com/64x-lunicorn/Corridor/blob/main/docs/adr/0008-the-app-attest-library-is-licensed-apache-2-0.md)

## Setup still needed

This repo has a README and a LICENSE and nothing else yet. Before ticket #172 (the first in build order) can start, it needs its own agent docs and CI gate: run `/64x-lunicorn:setup-project` here.
