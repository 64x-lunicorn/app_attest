defmodule AppAttest.AuthenticatorDataTest do
  use ExUnit.Case, async: true

  alias AppAttest.AuthenticatorData

  # The fixed 37-byte prefix every authenticator data value starts with:
  # a 32-byte App ID hash, a 1-byte flags field and a 4-byte Counter.
  @app_id_hash :crypto.hash(:sha256, "TEAMID12345.de.lunicorn.corridor")
  @flags 0x40
  @counter 7

  # Apple's nonce for the authenticator data below and this client data,
  # computed once and written down, so the expectation does not restate the
  # very construction `nonce/2` is being checked for.
  @client_data "request-specific-client-data"
  @expected_nonce "bcc5062801630ae0ac02f6782def3d961b10a6d46b8476a222154adffab28509"

  describe "parse/1" do
    test "parses the shared prefix alone, as an Assertion's authenticator data carries it" do
      data = <<@app_id_hash::binary, @flags, @counter::32-big>>

      assert {:ok, parsed} = AuthenticatorData.parse(data)
      assert parsed.app_id_hash == @app_id_hash
      assert parsed.flags == @flags
      assert parsed.counter == @counter
      assert parsed.aaguid == nil
      assert parsed.credential_id == nil
    end

    test "parses attested credential data too, as an Attestation's authenticator data carries it" do
      aaguid = "appattestdevelop"
      credential_id = :crypto.hash(:sha256, "device-key")
      cose_public_key = <<1, 2, 3>>

      data =
        <<@app_id_hash::binary, @flags, @counter::32-big, aaguid::binary,
          byte_size(credential_id)::16-big, credential_id::binary, cose_public_key::binary>>

      assert {:ok, parsed} = AuthenticatorData.parse(data)
      assert parsed.app_id_hash == @app_id_hash
      assert parsed.aaguid == aaguid
      assert parsed.credential_id == credential_id
    end

    test "rejects data shorter than the fixed 37-byte prefix" do
      assert AuthenticatorData.parse(<<1, 2, 3>>) == {:error, :invalid_authenticator_data}
    end

    test "rejects attested credential data whose credentialId runs past the end" do
      aaguid = "appattestdevelop"
      # Declares a 32-byte credential ID but supplies none.
      data = <<@app_id_hash::binary, @flags, @counter::32-big, aaguid::binary, 32::16-big>>

      assert AuthenticatorData.parse(data) == {:error, :invalid_authenticator_data}
    end
  end

  describe "nonce/2" do
    test "builds Apple's own nonce, the one an Attestation and an Assertion share" do
      auth_data = <<@app_id_hash::binary, @flags, @counter::32-big>>

      assert AuthenticatorData.nonce(auth_data, @client_data) ==
               Base.decode16!(@expected_nonce, case: :lower)
    end
  end

  describe "environment/1" do
    test "identifies Apple's development aaguid as the development environment" do
      assert AuthenticatorData.environment("appattestdevelop") == :development
    end

    test "identifies Apple's production aaguid as the production environment" do
      assert AuthenticatorData.environment("appattest" <> <<0, 0, 0, 0, 0, 0, 0>>) == :production
    end

    test "rejects an aaguid that is neither Apple's development nor production value" do
      assert AuthenticatorData.environment(<<0::128>>) == {:error, :unrecognized_environment}
    end

    test "rejects a missing aaguid instead of crashing" do
      assert AuthenticatorData.environment(nil) == {:error, :unrecognized_environment}
    end
  end
end
