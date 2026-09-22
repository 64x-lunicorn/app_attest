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

  The exact shape of what `validate/N` and `fetch/N` accept and return was
  this harness's own first draft, taken from architecture #174's Flow
  diagram; the ticket that first made a test pass was free to adjust it —
  #168 did, for `AppAttest.Attestation.validate/5`: it takes the raw,
  CBOR-encoded attestation object Apple's SDK produces, so its own fixtures
  (`AppAttest.Fixtures`, `test/support/`) are a real, Apple-issued
  development Attestation, reused under MIT license from
  uebelack/node-app-attest (Spec #166's own domain rule 6: proven against
  Attestations Apple actually issued, not only self-generated data). #169
  did too, for `AppAttest.Assertion.validate/4`: it drops the placeholder's
  environment parameters (#170's to add) and takes the raw, CBOR-encoded
  assertion object Apple's SDK produces; domain rule 6 names Attestations
  only, so its fixtures (`AppAttest.Fixtures.device_key_pair/0` and
  `assertion/3`) are self-generated instead. #170 did too, for
  `AppAttest.Assertion.validate/6`: it takes the environment the caller
  expects for this request as its own trailing parameter, compared against
  the stored environment #168 recorded, rather than the placeholder's
  approximation of that shape. #171 did too, for `AppAttest.RiskMetric.
  fetch/5`: the placeholder guessed a per-device lookup keyed by #168's key
  ID; #171's own primary-source check of Apple's "Assessing fraud risk"
  documentation found the real request keyed by the device's current
  *receipt* instead, with an explicit `root` (mirroring
  `AppAttest.Attestation.validate/5`'s own) and an `opts[:transport]` seam
  standing in for Apple's own endpoint - domain rule 6 names Attestations
  only, so `AppAttest.Fixtures.receipt/2`'s receipt is self-signed too.
  """

  use ExUnit.Case, async: true

  # A representative App ID: <Team ID>.<bundle ID>, per Apple's own format.
  @app_id "TEAMID12345.de.lunicorn.corridor"
  @key_id "device-key-id"

  defp stored_device(counter, environment \\ :development) do
    {private_key, public_key} = AppAttest.Fixtures.device_key_pair()

    %{
      key_id: @key_id,
      private_key: private_key,
      public_key: public_key,
      counter: counter,
      environment: environment
    }
  end

  describe "Attestation (built by #168)" do
    test "A genuine attestation is accepted" do
      assert {:ok, %{public_key: _public_key, counter: _start_counter, environment: :development}} =
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
    test "A genuine assertion with an increasing Counter is accepted" do
      device = stored_device(41)
      assertion = AppAttest.Fixtures.assertion(42, @app_id, device.private_key)

      assert {:ok, 42} =
               AppAttest.Assertion.validate(
                 assertion,
                 @app_id,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end

    test "A replayed assertion is rejected" do
      device = stored_device(42)
      assertion = AppAttest.Fixtures.assertion(42, @app_id, device.private_key)

      assert {:error, :counter_not_increasing} =
               AppAttest.Assertion.validate(
                 assertion,
                 @app_id,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end

    test "An assertion with a wrong App ID hash is rejected" do
      device = stored_device(41)
      assertion = AppAttest.Fixtures.assertion(42, @app_id, device.private_key)

      assert {:error, :app_id_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 "a-different-app-id",
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )
    end
  end

  describe "Development vs production (built by #170)" do
    test "A production assertion is never accepted as a development one, or the reverse" do
      device = stored_device(41, :development)
      # Otherwise entirely genuine: right signature, right App ID, an
      # increasing Counter. Only the caller's expected environment differs
      # from the one #168 recorded at attestation time, so this proves the
      # environment check rejects on its own, not by accident alongside
      # another check.
      assertion = AppAttest.Fixtures.assertion(42, @app_id, device.private_key)

      assert {:error, :environment_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 @app_id,
                 device.public_key,
                 device.counter,
                 device.environment,
                 _expected_environment = :production
               )
    end
  end

  describe "Risk metric (built by #171)" do
    test "The risk metric never changes a validation outcome" do
      device = stored_device(41)
      assertion = AppAttest.Fixtures.assertion(42, @app_id, device.private_key)

      # A genuine assertion that would otherwise be accepted...
      assert {:ok, 42} =
               AppAttest.Assertion.validate(
                 assertion,
                 @app_id,
                 device.public_key,
                 device.counter,
                 device.environment,
                 device.environment
               )

      # ...stays accepted no matter what Apple's risk metric says: fetching
      # it is a separate call the caller records, never an input to
      # validate/6. "A high number of distinct devices" is a receipt
      # fixture carrying that value in Apple's own risk-metric field,
      # handed back by a stand-in for Apple's own endpoint
      # (`AppAttest.RiskMetric`'s own `opts[:transport]` seam).
      chain = AppAttest.Fixtures.risk_metric_chain()
      a_high_number_of_distinct_devices = 99
      receipt = AppAttest.Fixtures.receipt(a_high_number_of_distinct_devices, chain)
      transport = fn _request -> {:ok, 200, Base.encode64(receipt)} end

      assert {:ok, %{risk_metric: ^a_high_number_of_distinct_devices}} =
               AppAttest.RiskMetric.fetch(
                 _previous_receipt = "device's-currently-stored-receipt",
                 device.environment,
                 AppAttest.Fixtures.device_check_key(),
                 chain.root,
                 transport: transport
               )
    end
  end

  describe "Every rejection is deliberately constructed, not assumed (spans #168 and #169)" do
    test "Every rejection case is proven, not only assumed" do
      device = stored_device(41)
      {wrong_private_key, _wrong_public_key} = AppAttest.Fixtures.device_key_pair()

      # One attestation or assertion per specific check this Spec names,
      # each built to fail exactly that check and nothing else: the three
      # Attestation ones deliberately mismatch one real Attestation's
      # challenge, App ID or trusted root at a time (#168); the two
      # Assertion ones are #169's own self-generated fixtures to build.
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
            AppAttest.Fixtures.assertion(device.counter, @app_id, device.private_key),
            @app_id,
            device.public_key,
            device.counter,
            device.environment,
            device.environment
          ),
        invalid_signature:
          AppAttest.Assertion.validate(
            AppAttest.Fixtures.assertion(device.counter + 1, @app_id, wrong_private_key),
            @app_id,
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
