# app_attest

Elixir library validating Apple's App Attest attestations and assertions, including the certificate chain, nonce, App ID hash, replay-safe Counter and Apple's per-device Risk metric, built for Corridor's server and published on Hex once proven against real devices. Terms live in [CONTEXT.md](CONTEXT.md), decisions in [docs/adr/](docs/adr/README.md).

## Project setup

`.claude/64x-lunicorn.yml` records forge, default branch, research, issues and the CI checks, and every 64x-lunicorn skill reads it. Change it by re-running `/64x-lunicorn:setup-project`, not by hand: the gate, the templates and these docs are generated from it.

## Conventions no validator can check

- `app_attest` holds no device state: every validation function takes the caller's stored state as input and returns what changed for the caller to persist, because storage belongs to the consuming server (Corridor ADR 0006, #174).
- Apple's App Attest root and the DeviceCheck signing key are explicit function parameters, never `Application` config or a compile-time flag, so tests can swap in a self-generated root side by side and the library never hardcodes anyone's key (#174).
- The Risk metric is returned and recorded but never decides acceptance or rejection (Corridor ADR 0007).

## Where the design lives

Specs, architecture, tickets and ADRs for this library live in `64x-lunicorn/Corridor`, not here: [Spec #166](https://github.com/64x-lunicorn/Corridor/issues/166), [Architecture #174](https://github.com/64x-lunicorn/Corridor/issues/174), [Wayfinder #175](https://github.com/64x-lunicorn/Corridor/issues/175), and the ADRs 0006 to 0008 in Corridor's `docs/adr/`. This repo's own `docs/adr/` holds only decisions made here.

## Changes

- Code, docs, messages and commits are English.
- Commits follow Conventional Commits in imperative mood.
- Work on a branch; `main` changes only through a squash-merged pull request that passed `CI gate`.
- Run `mix ci` before pushing; it runs every check the gate runs.
- Issues live in the GitHub issues of `64x-lunicorn/app_attest`, with the closed label set.
- Ideas live in `research/` and reach code only after promotion to a Spec.
