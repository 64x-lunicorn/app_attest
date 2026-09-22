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

  The fixtures below are placeholder data, not real CBOR or X.509 bytes: this
  ticket's own scope is the harness and the pending scenarios, not the wire
  format (architecture #174, "Touches"). The exact shape of what `validate/5`
  and `fetch/3` accept and return is this harness's own first draft, taken
  from architecture #174's Flow diagram; the ticket that first makes a test
  pass may still adjust it.
  """

  use ExUnit.Case, async: true

  # A representative App ID: <Team ID>.<bundle ID>, per Apple's own format.
  @app_id "TEAMID12345.de.lunicorn.corridor"
  @key_id "device-key-id"
  @challenge "server-issued-challenge"
  @apple_root :apple_app_attest_root

  defp stored_device(counter, environment \\ :development) do
    %{key_id: @key_id, public_key: :device_public_key, counter: counter, environment: environment}
  end

  describe "Attestation (built by #168)" do
    @tag pending: "AppAttest.Attestation does not exist yet (#168)"
    test "A genuine attestation is accepted" do
      attestation = %{
        certificate_chain: :leads_to_apple_app_attest_root,
        nonce: @challenge,
        app_id_hash: @app_id
      }

      assert {:ok, %{public_key: _public_key, counter: _start_counter}} =
               AppAttest.Attestation.validate(
                 attestation,
                 @key_id,
                 @challenge,
                 @app_id,
                 @apple_root
               )
    end

    @tag pending: "AppAttest.Attestation does not exist yet (#168)"
    test "An attestation with an untrusted certificate chain is rejected" do
      attestation = %{
        certificate_chain: :leads_to_an_untrusted_root,
        nonce: @challenge,
        app_id_hash: @app_id
      }

      assert {:error, :untrusted_root} =
               AppAttest.Attestation.validate(
                 attestation,
                 @key_id,
                 @challenge,
                 @app_id,
                 @apple_root
               )
    end

    @tag pending: "AppAttest.Attestation does not exist yet (#168)"
    test "An attestation with a wrong nonce is rejected" do
      attestation = %{
        certificate_chain: :leads_to_apple_app_attest_root,
        nonce: "a-different-nonce",
        app_id_hash: @app_id
      }

      assert {:error, :nonce_mismatch} =
               AppAttest.Attestation.validate(
                 attestation,
                 @key_id,
                 @challenge,
                 @app_id,
                 @apple_root
               )
    end

    @tag pending: "AppAttest.Attestation does not exist yet (#168)"
    test "An attestation with a wrong App ID hash is rejected" do
      attestation = %{
        certificate_chain: :leads_to_apple_app_attest_root,
        nonce: @challenge,
        app_id_hash: "a-different-app-id-hash"
      }

      assert {:error, :app_id_mismatch} =
               AppAttest.Attestation.validate(
                 attestation,
                 @key_id,
                 @challenge,
                 @app_id,
                 @apple_root
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

      # One self-generated attestation or assertion per specific check this
      # Spec names, each built to fail exactly that check and nothing else.
      results = %{
        untrusted_root:
          AppAttest.Attestation.validate(
            %{
              certificate_chain: :leads_to_an_untrusted_root,
              nonce: @challenge,
              app_id_hash: @app_id
            },
            @key_id,
            @challenge,
            @app_id,
            @apple_root
          ),
        nonce_mismatch:
          AppAttest.Attestation.validate(
            %{
              certificate_chain: :leads_to_apple_app_attest_root,
              nonce: "a-different-nonce",
              app_id_hash: @app_id
            },
            @key_id,
            @challenge,
            @app_id,
            @apple_root
          ),
        app_id_mismatch:
          AppAttest.Attestation.validate(
            %{
              certificate_chain: :leads_to_apple_app_attest_root,
              nonce: @challenge,
              app_id_hash: "a-different-app-id-hash"
            },
            @key_id,
            @challenge,
            @app_id,
            @apple_root
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
