# Scenarios tagged `:apple_endpoint` (test/app_attest/risk_metric_apple_test.exs)
# talk to Apple's real risk-metric endpoint and need the DeviceCheck credentials
# `AppAttest.AppleCredentials` documents. Without them there is nothing to run,
# so they are excluded rather than failed: a fresh clone with no Apple account
# runs the whole suite green.
apple_endpoint = if AppAttest.AppleCredentials.available?(), do: [], else: [:apple_endpoint]

ExUnit.start(exclude: apple_endpoint)
