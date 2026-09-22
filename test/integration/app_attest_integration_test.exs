defmodule AppAttest.IntegrationTest do
  @moduledoc """
  Black-box harness for Spec #166: every scenario drives `AppAttest.Attestation`,
  `AppAttest.Assertion` and `AppAttest.RiskMetric` only through their public
  functions, the way a real caller such as Corridor's server (Spec #165) would
  — never through their internals (architecture #174).

  Each test name is a Spec #166 scenario name, verbatim, and each is tagged
  `:pending` because the module it drives does not exist yet. `test_helper.exs`
  excludes `:pending` from the required `Test` check; the advisory
  `Pending scenarios` check (`.claude/64x-lunicorn.yml`) runs `mix test --only
  pending` so every one of them visibly fails for its missing behaviour, not
  for a bug in its own setup. A later ticket removes one test's `pending` tag
  at a time as it builds the behaviour that test names (order: #175).

  The Assertion, RiskMetric and dev/prod fixtures below are still placeholder
  data, not real CBOR or X.509 bytes: those tickets' own scope is not yet
  built. The exact shape of what `validate/5` and `fetch/3` accept and return
  is this harness's own first draft, taken from architecture #174's Flow
  diagram; the ticket that first makes a test pass may still adjust it —
  #168 did, for `AppAttest.Attestation.validate/5`: it takes the raw,
  CBOR-encoded attestation object Apple's SDK produces, so its own fixtures
  (`AppAttest.Fixtures`, `test/support/`) are a real, Apple-issued
  development Attestation, reused under MIT license from
  uebelack/node-app-attest (Spec #166's own domain rule 6: proven against
  Attestations Apple actually issued, not only self-generated data).
  """

  use ExUnit.Case, async: true

  # A representative App ID: <Team ID>.<bundle ID>, per Apple's own format.
  @app_id "TEAMID12345.de.lunicorn.corridor"
  @key_id "device-key-id"

  defp stored_device(counter, environment \\ :development) do
    %{key_id: @key_id, public_key: :device_public_key, counter: counter, environment: environment}
  end

  describe "Attestation (built by #168)" do
    test "A genuine attestation is accepted" do
      assert {:ok, %{public_key: _public_key, counter: _start_counter}} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default()
               )
    end

    test "An attestation with an untrusted certificate chain is rejected" do
      assert {:error, :untrusted_root} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.Fixtures.untrusted_root()
               )
    end

    test "An attestation with a wrong nonce is rejected" do
      assert {:error, :nonce_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 "a-different-challenge",
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default()
               )
    end

    test "An attestation with a wrong App ID hash is rejected" do
      assert {:error, :app_id_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 "a-different-app-id-hash",
                 AppAttest.RootCertificate.default()
               )
    end
  end

  describe "Assertion (built by #169)" do
    @tag pending: "AppAttest.Assertion does not exist yet (#169)"
    test "A genuine assertion with an increasing Counter is accepted" do
      device = stored_device(41)
      assertion = %{counter: 42, app_id_hash: @app_id}

      assert {:ok, %{counter: 42}} =
               AppAttest.Assertion.validate(
                 assertion,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end

    @tag pending: "AppAttest.Assertion does not exist yet (#169)"
    test "A replayed assertion is rejected" do
      device = stored_device(42)
      assertion = %{counter: 42, app_id_hash: @app_id}

      assert {:error, :counter_not_increasing} =
               AppAttest.Assertion.validate(
                 assertion,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end

    @tag pending: "AppAttest.Assertion does not exist yet (#169)"
    test "An assertion with a wrong App ID hash is rejected" do
      device = stored_device(41)
      assertion = %{counter: 42, app_id_hash: "a-different-app-id-hash"}

      assert {:error, :app_id_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end
  end

  describe "Development vs production (built by #170)" do
    @tag pending: "AppAttest.Assertion does not separate environments yet (#170)"
    test "A production assertion is never accepted as a development one, or the reverse" do
      device = stored_device(41, :development)
      assertion = %{counter: 42, app_id_hash: @app_id}

      assert {:error, :environment_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 device.public_key,
                 device.counter,
                 device.environment,
                 _expected_environment = :production
               )
    end
  end

  describe "Risk metric (built by #171)" do
    @tag pending: "AppAttest.RiskMetric does not exist yet (#171)"
    test "The risk metric never changes a validation outcome" do
      device = stored_device(41)
      assertion = %{counter: 42, app_id_hash: @app_id}
      device_check_key = %{key_id: "device-check-key-id", key: "device-check-private-key"}

      # A genuine assertion that would otherwise be accepted...
      assert {:ok, %{counter: 42}} =
               AppAttest.Assertion.validate(
                 assertion,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )

      # ...stays accepted no matter what Apple's risk metric says: fetching it
      # is a separate call the caller records, never an input to validate/5.
      # Simulating "a high number of distinct devices" needs a controllable
      # stand-in for Apple's own endpoint, which is #171's to build.
      assert {:ok, _risk_metric} =
               AppAttest.RiskMetric.fetch(device.key_id, device.environment, device_check_key)
    end
  end

  describe "Every rejection is deliberately constructed, not assumed (spans #168 and #169)" do
    @tag pending: "AppAttest.Attestation and AppAttest.Assertion do not exist yet (#168, #169)"
    test "Every rejection case is proven, not only assumed" do
      device = stored_device(41)

      # One attestation or assertion per specific check this Spec names,
      # each built to fail exactly that check and nothing else: the three
      # Attestation ones deliberately mismatch one real Attestation's
      # challenge, App ID or trusted root at a time (#168); the Assertion
      # one is #169's own self-generated fixture to build.
      results = %{
        untrusted_root:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            AppAttest.Fixtures.challenge(),
            AppAttest.Fixtures.app_id(),
            AppAttest.Fixtures.untrusted_root()
          ),
        nonce_mismatch:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            "a-different-challenge",
            AppAttest.Fixtures.app_id(),
            AppAttest.RootCertificate.default()
          ),
        app_id_mismatch:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            AppAttest.Fixtures.challenge(),
            "a-different-app-id-hash",
            AppAttest.RootCertificate.default()
          ),
        counter_not_increasing:
          AppAttest.Assertion.validate(
            %{counter: device.counter, app_id_hash: @app_id},
            device.public_key,
            device.counter,
            device.environment,
            device.environment
          )
      }

      for {reason, result} <- results do
        assert {:error, ^reason} = result
      end
    end
  end
end
