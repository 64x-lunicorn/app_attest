defmodule AppAttest.AssertionTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Assertion, Device, Fixtures, Typespecs}

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

    test "rejects an assertion whose authenticator data is not a CBOR byte string" do
      for auth_data <- ["a CBOR text string", nil, %CBOR.Tag{tag: 42, value: "tagged"}] do
        assert validate(self_generated_assertion(authenticator_data: auth_data)) ==
                 {:error, :invalid_assertion}
      end
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
