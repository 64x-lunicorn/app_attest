defmodule AppAttest.IntegrationTest do
  @moduledoc """
  Black-box harness for Spec 64x-lunicorn/Corridor#166: every scenario drives
  `AppAttest.Attestation`, `AppAttest.Assertion` and `AppAttest.RiskMetric`
  only through their public functions, the way a real caller such as
  Corridor's server would — never through their internals.

  Each test name is one of that Spec's scenario names, verbatim, and every one of
  them runs in the required `Test` check. The public functions it drives:

    * `AppAttest.Attestation.validate/6` - the raw, CBOR-encoded Attestation
      object Apple's SDK produces, its Key ID, the server's challenge, the
      App ID, the trusted root and the environment the caller expects;
      returns the `AppAttest.Device` the caller stores.
    * `AppAttest.Assertion.validate/5` - the raw, CBOR-encoded Assertion
      object, the `client_data` the device signed over, the App ID, the
      stored `AppAttest.Device` and the environment the caller expects;
      returns the Device with its Counter moved on.
    * `AppAttest.RiskMetric.fetch/4` - the stored `AppAttest.Device`, the
      DeviceCheck key, the trusted root and an `opts[:transport]` seam
      standing in for Apple's own endpoint; returns the Device with its
      Receipt moved on, alongside the risk metric.

  Its data comes from `AppAttest.Fixtures` (`test/support/`). The
  Attestation is a real, Apple-issued development Attestation, reused under
  MIT license from uebelack/node-app-attest, because of the Spec's domain
  rule "Validation is trusted only once it has been proven against
  Attestations Apple actually issued, not only against self-generated
  data." That rule names Attestations only, so the device key
  pair (`AppAttest.Fixtures.device_key_pair/0`), the Assertions
  (`AppAttest.Fixtures.assertion/5`) and the receipts
  (`AppAttest.Fixtures.receipt/2`) are self-generated, and so is the one
  Attestation the Risk metric scenario hands its Device on from
  (`AppAttest.Fixtures.self_generated_attestation/1`), because only the
  device holding its private key can sign the Assertions that follow it.
  Every rejection
  scenario changes one input at a time against otherwise valid data, so it
  fails for that one reason, per the domain rule "Every rejection case is
  deliberately constructed and tested, not left to accident."
  """

  use ExUnit.Case, async: true

  # A representative App ID: <Team ID>.<bundle ID>, per Apple's own format.
  @app_id "TEAMID12345.de.lunicorn.corridor"

  # The device's own private key (what only the device holds, to sign its
  # Assertions) and the `AppAttest.Device` the caller stored for it.
  defp stored_device(counter, environment \\ :development) do
    {private_key, public_key} = AppAttest.Fixtures.device_key_pair()

    {private_key,
     %AppAttest.Device{
       public_key: public_key,
       counter: counter,
       environment: environment,
       receipt: "device's-currently-stored-receipt"
     }}
  end

  describe "Attestation" do
    test "A genuine attestation is accepted" do
      assert {:ok,
              %AppAttest.Device{
                public_key: _public_key,
                counter: 0,
                environment: :development,
                receipt: receipt
              }} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default(),
                 :development
               )

      assert is_binary(receipt) and byte_size(receipt) > 0
    end

    test "An attestation with an untrusted certificate chain is rejected" do
      assert {:error, :untrusted_root} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.Fixtures.untrusted_root(),
                 :development
               )
    end

    test "An attestation with a wrong nonce is rejected" do
      assert {:error, :nonce_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 "a-different-challenge",
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default(),
                 :development
               )
    end

    test "An attestation with a wrong App ID hash is rejected" do
      assert {:error, :app_id_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 "a-different-app-id-hash",
                 AppAttest.RootCertificate.default(),
                 :development
               )
    end

    test "An attestation recorded under a Key ID that is not its own is rejected" do
      assert {:error, :key_id_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 a_key_id_of_another_key(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default(),
                 :development
               )
    end
  end

  # A well-formed Key ID (base64 of a SHA-256, like Apple's own) that
  # Apple's real fixture Attestation's attested public key does not yield.
  defp a_key_id_of_another_key do
    Base.encode64(:crypto.hash(:sha256, "another device's public key"))
  end

  describe "Assertion" do
    test "A genuine assertion with an increasing Counter is accepted" do
      {private_key, device} = stored_device(41)
      client_data = AppAttest.Fixtures.client_data()
      assertion = AppAttest.Fixtures.assertion(42, @app_id, client_data, private_key)

      assert {:ok, %AppAttest.Device{counter: 42}} =
               AppAttest.Assertion.validate(
                 assertion,
                 client_data,
                 @app_id,
                 device,
                 :development
               )
    end

    test "A replayed assertion is rejected" do
      {private_key, device} = stored_device(42)
      client_data = AppAttest.Fixtures.client_data()
      assertion = AppAttest.Fixtures.assertion(42, @app_id, client_data, private_key)

      assert {:error, :counter_not_increasing} =
               AppAttest.Assertion.validate(
                 assertion,
                 client_data,
                 @app_id,
                 device,
                 :development
               )
    end

    test "An assertion with a wrong App ID hash is rejected" do
      {private_key, device} = stored_device(41)
      client_data = AppAttest.Fixtures.client_data()
      assertion = AppAttest.Fixtures.assertion(42, @app_id, client_data, private_key)

      assert {:error, :app_id_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 client_data,
                 "a-different-app-id",
                 device,
                 :development
               )
    end

    test "An assertion signed for different clientData is rejected" do
      {private_key, device} = stored_device(41)

      assertion =
        AppAttest.Fixtures.assertion(
          42,
          @app_id,
          AppAttest.Fixtures.client_data(),
          private_key
        )

      assert {:error, :invalid_signature} =
               AppAttest.Assertion.validate(
                 assertion,
                 "a-different-client-data",
                 @app_id,
                 device,
                 :development
               )
    end
  end

  describe "Development vs production" do
    test "A production attestation is never accepted as a development one, or the reverse" do
      # Apple's real development Attestation, otherwise entirely genuine:
      # right chain, nonce, Key ID and App ID. Only the caller's expected
      # environment differs from the one its own aaguid yields, so this
      # proves the environment check rejects on its own.
      assert {:error, :environment_mismatch} =
               AppAttest.Attestation.validate(
                 AppAttest.Fixtures.attestation(),
                 AppAttest.Fixtures.key_id(),
                 AppAttest.Fixtures.challenge(),
                 AppAttest.Fixtures.app_id(),
                 AppAttest.RootCertificate.default(),
                 _expected_environment = :production
               )
    end

    test "A production assertion is never accepted as a development one, or the reverse" do
      {private_key, device} = stored_device(41, :development)
      client_data = AppAttest.Fixtures.client_data()
      # Otherwise entirely genuine: right signature, right App ID, an
      # increasing Counter. Only the caller's expected environment differs
      # from the one recorded at attestation time, so this proves the
      # environment check rejects on its own, not by accident alongside
      # another check.
      assertion = AppAttest.Fixtures.assertion(42, @app_id, client_data, private_key)

      assert {:error, :environment_mismatch} =
               AppAttest.Assertion.validate(
                 assertion,
                 client_data,
                 @app_id,
                 device,
                 _expected_environment = :production
               )
    end
  end

  describe "Risk metric" do
    test "The risk metric never changes a validation outcome" do
      # One Device, handed from Attestation to Assertion to Risk metric and
      # back to Assertion exactly as each returned it, the way a caller
      # stores and passes it on: never unpacked, never patched by hand.
      # The Attestation is self-generated, since only the device holding
      # its private key can sign the Assertions that follow.
      attestation = AppAttest.Fixtures.self_generated_attestation(app_id: @app_id)
      client_data = AppAttest.Fixtures.client_data()

      assert {:ok, device} =
               AppAttest.Attestation.validate(
                 attestation.attestation,
                 attestation.key_id,
                 attestation.challenge,
                 @app_id,
                 attestation.root,
                 :development
               )

      assert {:ok, device} =
               AppAttest.Assertion.validate(
                 AppAttest.Fixtures.assertion(1, @app_id, client_data, attestation.private_key),
                 client_data,
                 @app_id,
                 device,
                 :development
               )

      # "A high number of distinct devices" is a receipt fixture carrying
      # that value in Apple's own risk-metric field, handed back by a
      # stand-in for Apple's own endpoint (`AppAttest.RiskMetric`'s own
      # `opts[:transport]` seam).
      chain = AppAttest.Fixtures.risk_metric_chain()
      a_high_number_of_distinct_devices = 99
      receipt = AppAttest.Fixtures.receipt(a_high_number_of_distinct_devices, chain)
      transport = fn _request -> {:ok, 200, Base.encode64(receipt)} end

      assert {:ok, %{device: device, risk_metric: ^a_high_number_of_distinct_devices}} =
               AppAttest.RiskMetric.fetch(
                 device,
                 AppAttest.Fixtures.device_check_key(),
                 chain.root,
                 transport: transport
               )

      # The next genuine Assertion stays accepted no matter what Apple's
      # risk metric says: the risk metric is recorded, never an input to
      # validate/5 (Corridor ADR 0007).
      assert {:ok, %AppAttest.Device{counter: 2}} =
               AppAttest.Assertion.validate(
                 AppAttest.Fixtures.assertion(2, @app_id, client_data, attestation.private_key),
                 client_data,
                 @app_id,
                 device,
                 :development
               )
    end
  end

  describe "Every rejection is deliberately constructed, not assumed" do
    test "Every rejection case is proven, not only assumed" do
      {private_key, device} = stored_device(41)
      client_data = AppAttest.Fixtures.client_data()
      {wrong_private_key, _wrong_public_key} = AppAttest.Fixtures.device_key_pair()

      # One attestation or assertion per specific check this Spec names,
      # each built to fail exactly that check and nothing else: the four
      # Attestation ones deliberately mismatch one real Attestation's
      # challenge, Key ID, App ID or trusted root at a time;
      # the two Assertion ones are self-generated
      # (`AppAttest.Fixtures.assertion/5`).
      results = %{
        untrusted_root:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            AppAttest.Fixtures.challenge(),
            AppAttest.Fixtures.app_id(),
            AppAttest.Fixtures.untrusted_root(),
            :development
          ),
        nonce_mismatch:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            "a-different-challenge",
            AppAttest.Fixtures.app_id(),
            AppAttest.RootCertificate.default(),
            :development
          ),
        key_id_mismatch:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            a_key_id_of_another_key(),
            AppAttest.Fixtures.challenge(),
            AppAttest.Fixtures.app_id(),
            AppAttest.RootCertificate.default(),
            :development
          ),
        app_id_mismatch:
          AppAttest.Attestation.validate(
            AppAttest.Fixtures.attestation(),
            AppAttest.Fixtures.key_id(),
            AppAttest.Fixtures.challenge(),
            "a-different-app-id-hash",
            AppAttest.RootCertificate.default(),
            :development
          ),
        counter_not_increasing:
          AppAttest.Assertion.validate(
            AppAttest.Fixtures.assertion(
              41,
              @app_id,
              client_data,
              private_key
            ),
            client_data,
            @app_id,
            device,
            :development
          ),
        invalid_signature:
          AppAttest.Assertion.validate(
            AppAttest.Fixtures.assertion(
              42,
              @app_id,
              client_data,
              wrong_private_key
            ),
            client_data,
            @app_id,
            device,
            :development
          )
      }

      for {reason, result} <- results do
        assert {:error, ^reason} = result
      end
    end
  end
end
