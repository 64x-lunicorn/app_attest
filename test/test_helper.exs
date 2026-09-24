# Scenarios tagged `:pending` (test/integration/) name behaviour no ticket has
# built yet. Excluding them here is what keeps the required `Test` check
# green; the advisory `Pending scenarios` check runs them for real with
# `mix test --only pending`, so each one visibly fails for the missing
# behaviour instead of silently not running at all.

# Scenarios tagged `:apple_endpoint` (test/app_attest/risk_metric_apple_test.exs)
# talk to Apple's real risk-metric endpoint and need the DeviceCheck credentials
# `AppAttest.AppleCredentials` documents. Without them there is nothing to run,
# so they are excluded rather than failed: a fresh clone with no Apple account
# runs the whole suite green.
apple_endpoint = if AppAttest.AppleCredentials.available?(), do: [], else: [:apple_endpoint]

ExUnit.start(exclude: [:pending] ++ apple_endpoint)
