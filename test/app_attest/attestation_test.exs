defmodule AppAttest.AttestationTest do
  use ExUnit.Case, async: true

  alias AppAttest.Attestation

  # Apple's own nonce extension OID (architecture #174, `Attestation`'s own
  # `@nonce_extension_oid`): a DER SEQUENCE containing one element, a
  # context-tag [1] wrapping an OCTET STRING of the 32-byte nonce.
  # `check_nonce/3` only skips this fixed-size wrapper, never re-validates
  # its own DER structure, so any 6 bytes stand in for it here.
  @nonce_extension_oid {1, 2, 840, 113_635, 100, 8, 2}
  @nonce_extension_wrapper <<0, 0, 0, 0, 0, 0>>

  @app_id "TEAMID12345.de.lunicorn.corridor"
  @challenge "server-challenge"

  # A self-signed, entirely self-generated attestation object (no real
  # device involved): its authData is only the fixed 37-byte prefix, no
  # attested credential data, so `AuthenticatorData.parse/1` comes back
  # with `aaguid: nil` — a structurally valid but malformed Attestation no
  # genuine device would ever produce. Apple's real fixture cannot stand in
  # for this: its authData's aaguid is signed over by the nonce, so
  # altering it breaks the nonce check first and never reaches the
  # environment check this test targets. The leaf certificate is used as
  # both the chain and the trusted root (as `AppAttest.RootCertificate`'s
  # own tests do with a fresh self-signed certificate), so only the nonce
  # and App ID hash need to line up.
  defp self_generated_attestation_without_attested_credential_data do
    auth_data = <<:crypto.hash(:sha256, @app_id)::binary, 0, 0::32-big>>
    expected_nonce = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, @challenge))

    nonce_extension =
      {:Extension, @nonce_extension_oid, false, @nonce_extension_wrapper <> expected_nonce}

    leaf_der =
      :secp256r1
      |> X509.PrivateKey.new_ec()
      |> X509.Certificate.self_signed("/CN=Test Device",
        extensions: [apple_nonce: nonce_extension]
      )
      |> X509.Certificate.to_der()

    attestation_object =
      CBOR.encode(%{
        "fmt" => "apple-appattest",
        "attStmt" => %{"x5c" => [%CBOR.Tag{tag: :bytes, value: leaf_der}]},
        "authData" => %CBOR.Tag{tag: :bytes, value: auth_data}
      })

    {attestation_object, leaf_der}
  end

  describe "validate/5" do
    test "rejects an attestation whose aaguid is unrecognized instead of crashing" do
      {attestation_object, leaf_der} =
        self_generated_attestation_without_attested_credential_data()

      assert Attestation.validate(attestation_object, "key-id", @challenge, @app_id, leaf_der) ==
               {:error, :unrecognized_environment}
    end
  end
end
