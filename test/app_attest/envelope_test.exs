defmodule AppAttest.EnvelopeTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Envelope, Fixtures}

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  defp attestation_object(auth_data, x5c) do
    CBOR.encode(%{
      "fmt" => "apple-appattest",
      "attStmt" => %{"x5c" => x5c},
      "authData" => auth_data
    })
  end

  defp assertion_object(signature, auth_data) do
    CBOR.encode(%{"signature" => signature, "authenticatorData" => auth_data})
  end

  describe "decode_attestation/1" do
    test "decodes Apple's own attestation object into its raw fields" do
      assert {:ok, %{auth_data: auth_data, chain: [leaf | _intermediates], att_stmt: att_stmt}} =
               Envelope.decode_attestation(Fixtures.attestation())

      assert is_binary(auth_data)
      assert {:ok, _certificate} = X509.Certificate.from_der(leaf)
      # Kept whole for fields read elsewhere, such as the receipt (#11).
      assert Map.has_key?(att_stmt, "receipt")
    end

    test "unwraps the CBOR byte strings Apple's own fields are encoded as" do
      assert Envelope.decode_attestation(attestation_object(bytes("raw"), [bytes("der")])) ==
               {:ok, %{auth_data: "raw", chain: ["der"], att_stmt: %{"x5c" => [bytes("der")]}}}
    end

    test "rejects fields that are not CBOR byte strings instead of crashing" do
      for {auth_data, x5c} <- [
            {"a CBOR text string", [bytes("der")]},
            {nil, [bytes("der")]},
            {%CBOR.Tag{tag: 42, value: "tagged"}, [bytes("der")]},
            {bytes("raw"), [bytes("der"), "a CBOR text string"]},
            {bytes("raw"), []},
            {bytes("raw"), nil}
          ] do
        assert Envelope.decode_attestation(attestation_object(auth_data, x5c)) ==
                 {:error, :invalid_attestation}
      end
    end

    test "rejects input that is not CBOR at all without naming a cbor error" do
      for input <- [<<0xFF>>, <<>>, <<0x5A, 0, 0, 0, 9>>, :not_a_binary] do
        assert Envelope.decode_attestation(input) == {:error, :invalid_attestation}
      end
    end
  end

  describe "decode_assertion/1" do
    test "unwraps the CBOR byte strings Apple's own fields are encoded as" do
      assert Envelope.decode_assertion(assertion_object(bytes("sig"), bytes("raw"))) ==
               {:ok, %{signature: "sig", auth_data: "raw"}}
    end

    test "rejects fields that are not CBOR byte strings instead of crashing" do
      for {signature, auth_data} <- [
            {"a CBOR text string", bytes("raw")},
            {bytes("sig"), nil},
            {bytes("sig"), %CBOR.Tag{tag: 42, value: "tagged"}}
          ] do
        assert Envelope.decode_assertion(assertion_object(signature, auth_data)) ==
                 {:error, :invalid_assertion}
      end
    end

    test "rejects input that is not CBOR at all without naming a cbor error" do
      for input <- [<<0xFF>>, <<>>, <<0x5A, 0, 0, 0, 9>>, :not_a_binary] do
        assert Envelope.decode_assertion(input) == {:error, :invalid_assertion}
      end
    end
  end
end
