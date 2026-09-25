defmodule AppAttest.AttestationTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Attestation, Device, Fixtures, RootCertificate, Typespecs}

  # Apple's own nonce extension OID (architecture #174, `Attestation`'s own
  # `@nonce_extension_oid`): a DER SEQUENCE containing one element, a
  # context-tag [1] wrapping an OCTET STRING of the 32-byte nonce.
  # `check_nonce/3` only skips this fixed-size wrapper, never re-validates
  # its own DER structure, so any 6 bytes stand in for it here.
  @nonce_extension_oid {1, 2, 840, 113_635, 100, 8, 2}
  @nonce_extension_wrapper <<0, 0, 0, 0, 0, 0>>

  @app_id "TEAMID12345.de.lunicorn.corridor"
  @challenge "server-challenge"

  # A well-formed 37-byte authenticator data prefix, so a test that targets
  # one malformed field of an Attestation never trips over this one.
  @auth_data <<:crypto.hash(:sha256, @app_id)::binary, 0, 0::32-big>>

  # The same prefix followed by Apple's development aaguid and an empty
  # credential ID: the smallest authenticator data an Attestation is
  # accepted with, so a self-generated one can reach every check.
  @development_auth_data @auth_data <> "appattestdevelop" <> <<0::16>>

  # SHA-256 of the receipt the real fixture Attestation carries in its own
  # `attStmt.receipt` (3759 bytes), taken once from the fixture itself, so
  # the expected value does not come from the code under test.
  @fixture_receipt_sha256 "4e52998201baa1a9c2572f8560d5737bca64dbf62e7a240abddb08bf967df2ec"

  # Every rejection below happens before the chain is checked against a root,
  # so which root is passed cannot change the outcome.
  @any_root <<>>

  # A well-formed `apple-appattest` envelope whose `attStmt` and `authData`
  # are exactly what the caller passes, so one malformed field at a time can
  # be put in an otherwise intact Attestation (#212).
  defp attestation_object(att_stmt, auth_data) do
    CBOR.encode(%{
      "fmt" => "apple-appattest",
      "attStmt" => att_stmt,
      "authData" => auth_data
    })
  end

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  defp validate(attestation_object) do
    Attestation.validate(attestation_object, "key-id", @challenge, @app_id, @any_root)
  end

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
    self_generated_attestation(@auth_data, %{"receipt" => bytes("a-receipt")})
  end

  # A self-signed attestation object over `auth_data`, its `attStmt` being
  # the leaf certificate plus exactly `att_stmt_fields`, returned alongside
  # the leaf to pass as the trusted root.
  defp self_generated_attestation(auth_data, att_stmt_fields) do
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

    att_stmt = Map.put(att_stmt_fields, "x5c", [bytes(leaf_der)])
    {attestation_object(att_stmt, bytes(auth_data)), leaf_der}
  end

  describe "validate/5" do
    test "returns a Device carrying the receipt a genuine Attestation brought in attStmt.receipt" do
      assert {:ok, %Device{} = device} =
               Attestation.validate(
                 Fixtures.attestation(),
                 Fixtures.key_id(),
                 Fixtures.challenge(),
                 Fixtures.app_id(),
                 RootCertificate.default()
               )

      assert %Device{counter: 0, environment: :development, public_key: {{:ECPoint, _}, _}} =
               device

      assert Base.encode16(:crypto.hash(:sha256, device.receipt), case: :lower) ==
               @fixture_receipt_sha256
    end

    test "returns the self-generated receipt with the Device it attests" do
      {attestation_object, leaf_der} =
        self_generated_attestation(@development_auth_data, %{"receipt" => bytes("a-receipt")})

      assert {:ok, %Device{receipt: "a-receipt", counter: 0, environment: :development}} =
               Attestation.validate(attestation_object, "key-id", @challenge, @app_id, leaf_der)
    end

    test "rejects an otherwise genuine attestation whose attStmt carries no receipt" do
      {attestation_object, leaf_der} = self_generated_attestation(@development_auth_data, %{})

      assert Attestation.validate(attestation_object, "key-id", @challenge, @app_id, leaf_der) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation whose receipt is not a CBOR byte string" do
      {attestation_object, leaf_der} =
        self_generated_attestation(@development_auth_data, %{"receipt" => "a CBOR text string"})

      assert Attestation.validate(attestation_object, "key-id", @challenge, @app_id, leaf_der) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation object that is not CBOR at all as an invalid attestation" do
      assert validate(<<0xFF>>) == {:error, :invalid_attestation}
      assert validate(<<>>) == {:error, :invalid_attestation}
    end

    test "rejects an attestation whose aaguid is unrecognized instead of crashing" do
      {attestation_object, leaf_der} =
        self_generated_attestation_without_attested_credential_data()

      assert Attestation.validate(attestation_object, "key-id", @challenge, @app_id, leaf_der) ==
               {:error, :unrecognized_environment}
    end

    test "rejects a CBOR object that is not an apple-appattest attestation instead of crashing" do
      assert validate(CBOR.encode(%{"fmt" => "not-apple"})) == {:error, :invalid_attestation}

      assert validate(attestation_object("not a statement", bytes(@auth_data))) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation with an empty certificate chain instead of crashing" do
      assert validate(attestation_object(%{"x5c" => []}, bytes(@auth_data))) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation whose authData is not a CBOR byte string instead of crashing" do
      assert validate(attestation_object(%{"x5c" => [bytes(<<1, 2, 3>>)]}, "not-bytes")) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation with junk in place of a certificate instead of crashing" do
      assert validate(attestation_object(%{"x5c" => [bytes(<<1, 2, 3>>)]}, bytes(@auth_data))) ==
               {:error, :invalid_attestation}
    end
  end

  describe "rejection/0" do
    test "lists every reason validate/5 can return" do
      assert Typespecs.union_atoms(Attestation, :rejection) == [
               :invalid_attestation,
               :untrusted_root,
               :nonce_mismatch,
               :invalid_authenticator_data,
               :app_id_mismatch,
               :unrecognized_environment
             ]
    end
  end
end
