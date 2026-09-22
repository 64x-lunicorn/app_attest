defmodule AppAttest.AuthenticatorDataTest do
  use ExUnit.Case, async: true

  alias AppAttest.AuthenticatorData

  # The fixed 37-byte prefix every authenticator data value starts with:
  # a 32-byte App ID hash, a 1-byte flags field and a 4-byte Counter.
  @app_id_hash :crypto.hash(:sha256, "TEAMID12345.de.lunicorn.corridor")
  @flags 0x40
  @counter 7

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
end
