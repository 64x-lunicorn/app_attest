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

  # The real fixture's own key identifier, as Apple's SDK returned it and
  # the fixture file recorded it (`keyId`), written out here so the expected
  # value comes from the fixture's data rather than from the code under test.
  # It was cross-checked once, outside this code, with
  # `openssl x509 -pubkey | openssl ec -pubin -outform der | tail -c 65 |
  # openssl dgst -sha256 -binary | base64` over the fixture's leaf.
  @fixture_key_id "s/134MbeEEZDZKCvOTf+jZgNhpoDwdXZ8cKfTym8FUg="

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
  # device involved), returned as `{attestation_object, key_id, leaf_der}`:
  # `key_id` is the base64 SHA-256 of the leaf's own public key in X9.62
  # uncompressed point format, exactly as Apple's SDK derives it, and
  # `leaf_der` doubles as the trusted root (as `AppAttest.RootCertificate`'s
  # own tests do with a fresh self-signed certificate), so only what a test
  # deliberately varies can make it fail.
  #
  # By default its authenticator data is consistent with `key_id`: Counter
  # 0, Apple's development aaguid and a credentialId equal to the key
  # identifier. Options vary one field at a time:
  #
  # * `:counter` - the authenticator data's Counter (default 0).
  # * `:credential_id` - the credentialId (default: the key identifier).
  # * `:attested_credential_data` - `false` for only the 37-byte prefix,
  #   so `AuthenticatorData.parse/1` comes back with `aaguid: nil` — a
  #   structurally valid but malformed Attestation no genuine device would
  #   ever produce. Apple's real fixture cannot stand in for these: its
  #   authData is signed over by the nonce, so altering it breaks the nonce
  #   check first and never reaches the check a test targets.
  # * `:att_stmt` - the `attStmt` fields besides `x5c` (default: a receipt).
  defp self_generated_attestation(opts \\ []) do
    private_key = X509.PrivateKey.new_ec(:secp256r1)
    {{:ECPoint, public_key_point}, _parameters} = X509.PublicKey.derive(private_key)
    key_id_bytes = :crypto.hash(:sha256, public_key_point)

    prefix = <<:crypto.hash(:sha256, @app_id)::binary, 0, Keyword.get(opts, :counter, 0)::32-big>>
    credential_id = Keyword.get(opts, :credential_id, key_id_bytes)

    auth_data =
      if Keyword.get(opts, :attested_credential_data, true) do
        prefix <> "appattestdevelop" <> <<byte_size(credential_id)::16>> <> credential_id
      else
        prefix
      end

    expected_nonce = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, @challenge))

    nonce_extension =
      {:Extension, @nonce_extension_oid, false, @nonce_extension_wrapper <> expected_nonce}

    leaf_der =
      private_key
      |> X509.Certificate.self_signed("/CN=Test Device",
        extensions: [apple_nonce: nonce_extension]
      )
      |> X509.Certificate.to_der()

    att_stmt =
      opts
      |> Keyword.get(:att_stmt, %{"receipt" => bytes("a-receipt")})
      |> Map.put("x5c", [bytes(leaf_der)])

    {attestation_object(att_stmt, bytes(auth_data)), Base.encode64(key_id_bytes), leaf_der}
  end

  defp validate_fixture(key_id) do
    Attestation.validate(
      Fixtures.attestation(),
      key_id,
      Fixtures.challenge(),
      Fixtures.app_id(),
      RootCertificate.default()
    )
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

    test "accepts Apple's real fixture Attestation for its own key_id" do
      assert Fixtures.key_id() == @fixture_key_id
      assert {:ok, %Device{counter: 0}} = validate_fixture(@fixture_key_id)
    end

    test "Apple's real fixture binds its key_id to its public key, credentialId and Counter 0" do
      # Read straight off the fixture's own bytes, independent of
      # `Attestation`: the credential certificate's public key in X9.62
      # uncompressed point format (0x04 || X || Y) and the authenticator
      # data's Counter and credentialId.
      [leaf_der | _intermediates] = Fixtures.certificate_chain()

      {{:ECPoint, <<0x04, _x_and_y::binary-size(64)>> = point}, _parameters} =
        leaf_der |> X509.Certificate.from_der!() |> X509.Certificate.public_key()

      {:ok, %{auth_data: auth_data}} =
        AppAttest.Envelope.decode_attestation(Fixtures.attestation())

      <<_app_id_hash::binary-size(32), _flags, counter::32-big, _aaguid::binary-size(16),
        credential_id_length::16-big, credential_id::binary-size(credential_id_length),
        _cose_key::binary>> = auth_data

      assert Base.encode64(:crypto.hash(:sha256, point)) == @fixture_key_id
      assert Base.encode64(credential_id) == @fixture_key_id
      assert counter == 0
    end

    test "rejects Apple's real fixture Attestation for a key_id that is not its public key's hash" do
      other_key_id = Base.encode64(:crypto.hash(:sha256, "a different key"))

      assert validate_fixture(other_key_id) == {:error, :key_id_mismatch}
    end

    test "rejects a key_id that is not base64 instead of raising" do
      assert validate_fixture("not base64!") == {:error, :key_id_mismatch}
      assert validate_fixture("") == {:error, :key_id_mismatch}
    end

    test "rejects a key_id mismatch before an App ID mismatch, in Apple's order" do
      assert Attestation.validate(
               Fixtures.attestation(),
               Base.encode64(:crypto.hash(:sha256, "a different key")),
               Fixtures.challenge(),
               "TEAMID1234.not.this.app",
               RootCertificate.default()
             ) == {:error, :key_id_mismatch}
    end

    test "rejects a self-generated Attestation whose credentialId differs from the key_id" do
      {attestation_object, key_id, leaf_der} =
        self_generated_attestation(credential_id: :crypto.hash(:sha256, "another credential"))

      assert Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der) ==
               {:error, :key_id_mismatch}
    end

    test "rejects a self-generated Attestation whose Counter is not 0" do
      {attestation_object, key_id, leaf_der} = self_generated_attestation(counter: 1)

      assert Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der) ==
               {:error, :counter_not_zero}
    end

    test "checks the App ID before the Counter, in Apple's order" do
      {attestation_object, key_id, leaf_der} = self_generated_attestation(counter: 1)

      assert Attestation.validate(attestation_object, key_id, @challenge, "OTHER.app", leaf_der) ==
               {:error, :app_id_mismatch}
    end

    test "returns the self-generated receipt with the Device it attests" do
      {attestation_object, key_id, leaf_der} = self_generated_attestation()

      assert {:ok, %Device{receipt: "a-receipt", counter: 0, environment: :development}} =
               Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der)
    end

    test "rejects an otherwise genuine attestation whose attStmt carries no receipt" do
      {attestation_object, key_id, leaf_der} = self_generated_attestation(att_stmt: %{})

      assert Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation whose receipt is not a CBOR byte string" do
      {attestation_object, key_id, leaf_der} =
        self_generated_attestation(att_stmt: %{"receipt" => "a CBOR text string"})

      assert Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der) ==
               {:error, :invalid_attestation}
    end

    test "rejects an attestation object that is not CBOR at all as an invalid attestation" do
      assert validate(<<0xFF>>) == {:error, :invalid_attestation}
      assert validate(<<>>) == {:error, :invalid_attestation}
    end

    test "rejects an attestation whose aaguid is unrecognized instead of crashing" do
      {attestation_object, key_id, leaf_der} =
        self_generated_attestation(attested_credential_data: false)

      assert Attestation.validate(attestation_object, key_id, @challenge, @app_id, leaf_der) ==
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
               :key_id_mismatch,
               :invalid_authenticator_data,
               :app_id_mismatch,
               :counter_not_zero,
               :unrecognized_environment
             ]
    end
  end
end
