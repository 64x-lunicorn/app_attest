defmodule AppAttest.AssertionTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Assertion, Device, Fixtures, Typespecs}

  @app_id "TEAMID12345.de.lunicorn.corridor"

  # A well-formed 37-byte authenticator data prefix and a signature-shaped
  # value, so a test that targets one missing key of an Assertion never
  # trips over the other one (#212).
  @auth_data <<:crypto.hash(:sha256, @app_id)::binary, 0, 1::32-big>>
  @signature <<0::256>>

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

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

  defp device(public_key, counter) do
    %Device{
      public_key: public_key,
      counter: counter,
      environment: :development,
      receipt: "the-device's-current-receipt"
    }
  end

  describe "validate/5" do
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
      assert validate(<<0xFF>>) == {:error, :invalid_assertion}
      assert validate(<<>>) == {:error, :invalid_assertion}
    end

    test "rejects an assertion object without a signature instead of crashing" do
      assertion_object = CBOR.encode(%{"authenticatorData" => bytes(@auth_data)})

      assert validate(assertion_object) == {:error, :invalid_assertion}
    end

    test "rejects an assertion object without authenticator data instead of crashing" do
      assertion_object = CBOR.encode(%{"signature" => bytes(@signature)})

      assert validate(assertion_object) == {:error, :invalid_assertion}
    end
  end

  describe "rejection/0" do
    test "lists every reason validate/5 can return" do
      assert Typespecs.union_atoms(Assertion, :rejection) == [
               :environment_mismatch,
               :invalid_assertion,
               :invalid_authenticator_data,
               :invalid_signature,
               :app_id_mismatch,
               :counter_not_increasing
             ]
    end
  end
end
