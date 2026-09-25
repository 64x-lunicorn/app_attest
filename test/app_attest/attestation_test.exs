defmodule AppAttest.AttestationTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Attestation, Device, Fixtures, RootCertificate, Typespecs}

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

  # Validates a self-generated Attestation (`Fixtures.self_generated_attestation/1`)
  # for exactly what it was built for, expecting `environment`.
  defp validate_self_generated(attestation, environment \\ :development) do
    Attestation.validate(
      attestation.attestation,
      attestation.key_id,
      attestation.challenge,
      attestation.app_id,
      attestation.root,
      environment
    )
  end

  # Validates raw bytes that are not a well-formed Attestation object at
  # all. Decoding fails before any key, challenge or root is looked at, so
  # which ones are passed cannot change the outcome.
  defp validate_bytes(attestation_object) do
    attestation = Fixtures.self_generated_attestation()
    validate_self_generated(%{attestation | attestation: attestation_object})
  end

  defp validate_fixture(key_id) do
    Attestation.validate(
      Fixtures.attestation(),
      key_id,
      Fixtures.challenge(),
      Fixtures.app_id(),
      RootCertificate.default(),
      :development
    )
  end

  describe "validate/6" do
    test "returns a Device carrying the receipt a genuine Attestation brought in attStmt.receipt" do
      assert {:ok, %Device{} = device} =
               Attestation.validate(
                 Fixtures.attestation(),
                 Fixtures.key_id(),
                 Fixtures.challenge(),
                 Fixtures.app_id(),
                 RootCertificate.default(),
                 :development
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

      auth_data = Fixtures.attestation_authenticator_data()

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
               RootCertificate.default(),
               :development
             ) == {:error, :key_id_mismatch}
    end

    test "rejects a self-generated Attestation whose credentialId differs from the key_id" do
      attestation =
        Fixtures.self_generated_attestation(
          credential_id: :crypto.hash(:sha256, "another credential")
        )

      assert validate_self_generated(attestation) == {:error, :key_id_mismatch}
    end

    test "rejects a self-generated Attestation whose Counter is not 0" do
      attestation = Fixtures.self_generated_attestation(counter: 1)

      assert validate_self_generated(attestation) == {:error, :counter_not_zero}
    end

    test "checks the App ID before the Counter, in Apple's order" do
      attestation = Fixtures.self_generated_attestation(counter: 1)

      assert validate_self_generated(%{attestation | app_id: "OTHER.app"}) ==
               {:error, :app_id_mismatch}
    end

    test "returns the self-generated receipt with the Device it attests" do
      attestation = Fixtures.self_generated_attestation()

      assert {:ok, %Device{receipt: "a-receipt", counter: 0, environment: :development}} =
               validate_self_generated(attestation)
    end

    test "rejects an otherwise genuine attestation whose attStmt carries no receipt" do
      attestation = Fixtures.self_generated_attestation(receipt: :omit)

      assert validate_self_generated(attestation) == {:error, :invalid_attestation}
    end

    test "rejects an attestation whose receipt is not a CBOR byte string" do
      for receipt <- ["a CBOR text string", nil, %CBOR.Tag{tag: 42, value: "tagged"}] do
        attestation = Fixtures.self_generated_attestation(receipt: receipt)

        assert validate_self_generated(attestation) == {:error, :invalid_attestation}
      end
    end

    test "rejects an attestation object that is not CBOR at all as an invalid attestation" do
      # The last one declares a byte string longer than what follows.
      for input <- [<<0xFF>>, <<>>, <<0x5A, 0, 0, 0, 9>>] do
        assert validate_bytes(input) == {:error, :invalid_attestation}
      end
    end

    test "rejects an attestation object that is not even bytes without naming a cbor error" do
      assert validate_bytes(:not_a_binary) == {:error, :invalid_attestation}
    end

    test "rejects an attestation whose aaguid is unrecognized instead of crashing" do
      attestation = Fixtures.self_generated_attestation(attested_credential_data: false)

      assert validate_self_generated(attestation) == {:error, :unrecognized_environment}
    end

    test "rejects a production Attestation where a development one is expected" do
      # Apple's production aaguid: "appattest" padded with seven 0x00 bytes.
      attestation = Fixtures.self_generated_attestation(aaguid: "appattest" <> <<0::56>>)

      assert validate_self_generated(attestation, :development) ==
               {:error, :environment_mismatch}
    end

    test "accepts a production Attestation where a production one is expected" do
      attestation = Fixtures.self_generated_attestation(aaguid: "appattest" <> <<0::56>>)

      assert {:ok, %Device{environment: :production}} =
               validate_self_generated(attestation, :production)
    end

    test "rejects a CBOR object that is not an apple-appattest attestation instead of crashing" do
      assert validate_self_generated(Fixtures.self_generated_attestation(fmt: "not-apple")) ==
               {:error, :invalid_attestation}

      assert validate_self_generated(
               Fixtures.self_generated_attestation(att_stmt: "not a statement")
             ) == {:error, :invalid_attestation}
    end

    test "rejects an attestation with an empty or missing certificate chain instead of crashing" do
      for x5c <- [[], nil, :omit] do
        attestation = Fixtures.self_generated_attestation(x5c: x5c)

        assert validate_self_generated(attestation) == {:error, :invalid_attestation}
      end
    end

    test "rejects an attestation whose certificate chain holds something other than CBOR byte strings" do
      [leaf_der | _intermediates] = Fixtures.certificate_chain()

      for x5c <- [
            ["a CBOR text string"],
            [Fixtures.cbor_bytes(leaf_der), "a CBOR text string"]
          ] do
        attestation = Fixtures.self_generated_attestation(x5c: x5c)

        assert validate_self_generated(attestation) == {:error, :invalid_attestation}
      end
    end

    test "rejects an attestation whose authData is not a CBOR byte string instead of crashing" do
      for auth_data <- ["not-bytes", nil, %CBOR.Tag{tag: 42, value: "tagged"}, :omit] do
        attestation = Fixtures.self_generated_attestation(auth_data: auth_data)

        assert validate_self_generated(attestation) == {:error, :invalid_attestation}
      end
    end

    test "rejects an attestation with junk in place of a certificate instead of crashing" do
      attestation = Fixtures.self_generated_attestation(x5c: [Fixtures.cbor_bytes(<<1, 2, 3>>)])

      assert validate_self_generated(attestation) == {:error, :invalid_attestation}
    end

    test "rejects Apple's real fixture with junk in place of its intermediate instead of crashing" do
      [leaf_der | _intermediates] = Fixtures.certificate_chain()

      assert Attestation.validate(
               Fixtures.attestation_with_chain([leaf_der, <<1, 2, 3>>]),
               Fixtures.key_id(),
               Fixtures.challenge(),
               Fixtures.app_id(),
               RootCertificate.default(),
               :development
             ) == {:error, :invalid_attestation}
    end

    # OTP's certificate decoding and path validation raise or exit in many
    # different ways for DER that is damaged deep inside, not only for
    # junk. A fixed seed keeps the positions, and so the test, deterministic.
    test "rejects Apple's real fixture with any single byte of a certificate changed instead of crashing" do
      chain = Fixtures.certificate_chain()
      state = :rand.seed_s(:exsss, {16, 16, 16})

      Enum.reduce(0..(length(chain) - 1), state, fn index, state ->
        Enum.reduce(1..200, state, fn _mutation, state ->
          der = Enum.at(chain, index)
          {position, state} = :rand.uniform_s(byte_size(der), state)
          mutated_chain = List.replace_at(chain, index, Fixtures.flip_byte(der, position - 1))

          result =
            Attestation.validate(
              Fixtures.attestation_with_chain(mutated_chain),
              Fixtures.key_id(),
              Fixtures.challenge(),
              Fixtures.app_id(),
              RootCertificate.default(),
              :development
            )

          # A changed certificate is never trusted, whether it still
          # decodes or not.
          assert result in [{:error, :invalid_attestation}, {:error, :untrusted_root}]
          state
        end)
      end)
    end

    test "rejects Apple's real fixture against a root that is not a certificate instead of crashing" do
      assert Attestation.validate(
               Fixtures.attestation(),
               Fixtures.key_id(),
               Fixtures.challenge(),
               Fixtures.app_id(),
               <<1, 2, 3>>,
               :development
             ) == {:error, :untrusted_root}
    end
  end

  describe "rejection/0" do
    test "lists every reason validate/6 can return" do
      assert Typespecs.union_atoms(Attestation, :rejection) == [
               :invalid_attestation,
               :untrusted_root,
               :nonce_mismatch,
               :key_id_mismatch,
               :invalid_authenticator_data,
               :app_id_mismatch,
               :counter_not_zero,
               :unrecognized_environment,
               :environment_mismatch
             ]
    end
  end
end
