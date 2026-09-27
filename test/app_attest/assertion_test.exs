defmodule AppAttest.AssertionTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Assertion, Device, Fixtures}

  @app_id "TEAMID12345.de.lunicorn.corridor"

  # Every rejection below happens before the signature is checked, so which
  # key the Assertion is validated against cannot change the outcome.
  defp validate(assertion_object) do
    {_private_key, public_key} = Fixtures.device_key_pair()

    Assertion.validate(
      assertion_object,
      Fixtures.client_data(),
      @app_id,
      device(public_key, 0),
      :development
    )
  end

  # An otherwise genuine Assertion with one envelope field made wrong by
  # `opts` (`Fixtures.assertion/5`).
  defp self_generated_assertion(opts) do
    {private_key, _public_key} = Fixtures.device_key_pair()
    Fixtures.assertion(1, @app_id, Fixtures.client_data(), private_key, opts)
  end

  defp device(public_key, counter) do
    %Device{
      public_key: public_key,
      counter: counter,
      environment: :development,
      receipt: "the-device's-current-receipt"
    }
  end

  describe "validate/5" do
    test "accepts a genuine Assertion for a Device serialised and read back byte for byte" do
      attestation = Fixtures.self_generated_attestation()

      {:ok, device} =
        AppAttest.Attestation.validate(
          attestation.attestation,
          attestation.key_id,
          attestation.challenge,
          attestation.app_id,
          attestation.trust,
          :development
        )

      # What a caller's storage holds: plain JSON, every binary base64, with
      # no knowledge of X.509 or of OTP's own key terms.
      stored =
        IO.iodata_to_binary(
          :json.encode(%{
            "public_key" => Base.encode64(device.public_key),
            "counter" => device.counter,
            "environment" => Atom.to_string(device.environment),
            "receipt" => Base.encode64(device.receipt)
          })
        )

      read_back = :json.decode(stored)

      restored = %Device{
        public_key: Base.decode64!(read_back["public_key"]),
        counter: read_back["counter"],
        environment: String.to_existing_atom(read_back["environment"]),
        receipt: Base.decode64!(read_back["receipt"])
      }

      client_data = Fixtures.client_data()

      assertion_object =
        Fixtures.assertion(1, attestation.app_id, client_data, attestation.private_key)

      assert {:ok, %Device{counter: 1}} =
               Assertion.validate(
                 assertion_object,
                 client_data,
                 attestation.app_id,
                 restored,
                 :development
               )
    end

    test "returns the same Device with only its Counter moved on" do
      {private_key, public_key} = Fixtures.device_key_pair()
      device = device(public_key, 41)
      client_data = Fixtures.client_data()
      assertion_object = Fixtures.assertion(42, @app_id, client_data, private_key)

      assert Assertion.validate(assertion_object, client_data, @app_id, device, :development) ==
               {:ok,
                %Device{
                  public_key: public_key,
                  counter: 42,
                  environment: :development,
                  receipt: "the-device's-current-receipt"
                }}
    end

    test "rejects a Device whose public key is not a DER-encoded key as an invalid signature" do
      {private_key, _public_key} = Fixtures.device_key_pair()
      client_data = Fixtures.client_data()
      assertion_object = Fixtures.assertion(42, @app_id, client_data, private_key)

      assert Assertion.validate(
               assertion_object,
               client_data,
               @app_id,
               device("not a DER-encoded public key", 41),
               :development
             ) == {:error, :invalid_signature}
    end

    test "rejects an Assertion expected in a different environment than the Device's" do
      {private_key, public_key} = Fixtures.device_key_pair()
      client_data = Fixtures.client_data()
      assertion_object = Fixtures.assertion(42, @app_id, client_data, private_key)

      assert Assertion.validate(
               assertion_object,
               client_data,
               @app_id,
               device(public_key, 41),
               :production
             ) == {:error, :environment_mismatch}
    end

    test "rejects an assertion object that is not CBOR at all as an invalid assertion" do
      # The last one declares a byte string longer than what follows.
      for input <- [<<0xFF>>, <<>>, <<0x5A, 0, 0, 0, 9>>] do
        assert validate(input) == {:error, :invalid_assertion}
      end
    end

    test "rejects an assertion object that is not even bytes without naming a cbor error" do
      assert validate(:not_a_binary) == {:error, :invalid_assertion}
    end

    test "rejects an assertion object without a signature instead of crashing" do
      assert validate(self_generated_assertion(signature: :omit)) == {:error, :invalid_assertion}
    end

    test "rejects an assertion object without authenticator data instead of crashing" do
      assert validate(self_generated_assertion(authenticator_data: :omit)) ==
               {:error, :invalid_assertion}
    end

    test "rejects an assertion whose signature is not a CBOR byte string" do
      for signature <- ["a CBOR text string", nil, %CBOR.Tag{tag: 42, value: "tagged"}] do
        assert validate(self_generated_assertion(signature: signature)) ==
                 {:error, :invalid_assertion}
      end
    end

    test "rejects authenticator data shorter than its 37-byte prefix" do
      assert validate(
               self_generated_assertion(authenticator_data: Fixtures.cbor_bytes(<<1, 2, 3>>))
             ) ==
               {:error, :invalid_authenticator_data}
    end

    test "rejects authenticator data whose bytes after the prefix are truncated" do
      # A 16-byte aaguid declaring a 32-byte credentialId it never supplies.
      truncated = Fixtures.authenticator_data(@app_id) <> "appattestdevelop" <> <<32::16>>

      assert validate(
               self_generated_assertion(authenticator_data: Fixtures.cbor_bytes(truncated))
             ) ==
               {:error, :invalid_authenticator_data}
    end

    test "rejects an assertion whose authenticator data is not a CBOR byte string" do
      for auth_data <- ["a CBOR text string", nil, %CBOR.Tag{tag: 42, value: "tagged"}] do
        assert validate(self_generated_assertion(authenticator_data: auth_data)) ==
                 {:error, :invalid_assertion}
      end
    end
  end
end
