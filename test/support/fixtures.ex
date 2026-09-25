defmodule AppAttest.Fixtures do
  @moduledoc """
  Every input a test feeds the library, in one place: a real, Apple-issued
  development Attestation, reused under MIT license (notice kept, see the
  repository's own `NOTICE` file) from `uebelack/node-app-attest`'s
  `test/fixtures/attestation-development.json`
  (https://github.com/uebelack/node-app-attest), and builders for
  self-generated authenticator data, Attestations, Assertions, Receipts
  and certificate chains, plus one byte-mutation helper (`flip_byte/2`).

  The domain rule of Spec 64x-lunicorn/Corridor#166 "Validation is trusted
  only once it has been proven against Attestations Apple actually issued,
  not only against self-generated data" is why the "genuine Attestation is
  accepted" scenario is proven against these real bytes rather than
  self-generated ones. The Attestation rejection scenarios reuse the very
  same bytes with one input to `AppAttest.Attestation.validate/6`
  deliberately wrong at a time, so each is proven to fail for that one
  specific reason ("Every rejection case is deliberately constructed and
  tested, not left to accident"). A wrong field inside the Attestation
  itself cannot be made in Apple's bytes without breaking its nonce first,
  so `self_generated_attestation/1` builds those. No real device Assertion
  is recorded, so `device_key_pair/0` and `assertion/5` build self-signed
  Assertion data instead.

  Every builder derives its bytes from Apple's documented formats alone,
  never by calling into the library for the very construction a test
  checks (Apple's nonce included), and never through the library's
  internal CBOR envelope decoding: an input built the way the code under test
  builds it would pass by construction.
  """

  @fixture_path Path.join(__DIR__, "fixtures/attestation-development.json")
  @external_resource @fixture_path

  @fixture @fixture_path |> File.read!() |> :json.decode()

  # From the same reference repository's test suite, alongside the fixture
  # file: https://github.com/uebelack/node-app-attest/blob/main/test/verifyAttestation.test.js
  @team_identifier "V8H6LQ9448"
  @bundle_identifier "io.uebelacker.AppAttestExample"

  # Apple's own receipt attribute numbers ("Assessing fraud risk", the same
  # table `AppAttest.Receipt` reads). Field 6 ("Receipt Type") is always
  # "RECEIPT" for a receipt fetched from the risk-metric endpoint, never
  # "ATTEST" (the value the one accompanying an Attestation object carries).
  # What `self_generated_attestation/1` is built for unless told otherwise.
  @self_generated_app_id "TEAMID12345.de.lunicorn.corridor"
  @self_generated_challenge "server-challenge"

  # Apple's own nonce extension OID in the credential certificate: a DER
  # SEQUENCE containing one element, a context-tag [1] wrapping an OCTET
  # STRING of the 32-byte nonce. All three lengths are fixed, so any 6 bytes
  # stand in for the wrapper; the library only skips it.
  @nonce_extension_oid {1, 2, 840, 113_635, 100, 8, 2}
  @nonce_extension_wrapper <<0, 0, 0, 0, 0, 0>>

  @receipt_type_field 6
  @risk_metric_field 17
  @not_before_field 19
  @expiration_time_field 21

  # Two fixed dates, far enough apart that a test can tell them apart, in the
  # RFC 3339 form Apple's own receipt date fields use.
  @receipt_not_before ~U[2026-01-01 00:00:00Z]
  @receipt_expiration_time ~U[2026-01-08 00:00:00Z]

  # RFC 5652: pkcs7-signedData and id-data, plus the two algorithm OIDs every
  # receipt this module builds is signed with.
  @signed_data_oid {1, 2, 840, 113_549, 1, 7, 2}
  @data_oid {1, 2, 840, 113_549, 1, 7, 1}
  @sha256_oid {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @ecdsa_with_sha256_oid {1, 2, 840, 10045, 4, 3, 2}

  @doc "The raw, CBOR-encoded Attestation object, as Apple's SDK produced it."
  @spec attestation() :: binary()
  def attestation, do: Base.decode64!(@fixture["attestation"])

  @doc "The one-time server challenge this Attestation was created for."
  @spec challenge() :: binary()
  def challenge, do: Base.decode64!(@fixture["challenge"])

  @doc "The app-supplied key identifier for this Attestation, base64-encoded."
  @spec key_id() :: String.t()
  def key_id, do: @fixture["keyId"]

  @doc """
  This Attestation's leaf-first certificate chain (Apple's `x5c`),
  DER-encoded, read straight out of the CBOR attestation object.
  """
  @spec certificate_chain() :: [AppAttest.RootCertificate.der(), ...]
  def certificate_chain do
    Enum.map(apple_attestation_map()["attStmt"]["x5c"], &unwrap_bytes/1)
  end

  @doc """
  The raw authenticator data (`authData`) of this Attestation, read
  straight out of the CBOR attestation object.
  """
  @spec attestation_authenticator_data() :: binary()
  def attestation_authenticator_data, do: unwrap_bytes(apple_attestation_map()["authData"])

  @doc """
  The real, Apple-issued `ATTEST` Receipt this Attestation carries in its
  own `attStmt.receipt`, read straight out of the CBOR attestation object.
  """
  @spec attestation_receipt() :: binary()
  def attestation_receipt, do: unwrap_bytes(apple_attestation_map()["attStmt"]["receipt"])

  @doc """
  This Attestation, byte for byte, except for its `x5c` certificate chain,
  replaced by `chain` (DER, leaf first): the real Attestation with one
  certificate damaged, for the rejections a damaged chain must cause.
  """
  @spec attestation_with_chain([binary()]) :: binary()
  def attestation_with_chain(chain) do
    apple_attestation_map()
    |> put_in(["attStmt", "x5c"], Enum.map(chain, &cbor_bytes/1))
    |> CBOR.encode()
  end

  defp apple_attestation_map do
    {:ok, decoded, ""} = CBOR.decode(attestation())
    decoded
  end

  @doc "This Attestation's App ID: `\"<Team ID>.<bundle ID>\"`."
  @spec app_id() :: String.t()
  def app_id, do: "#{@team_identifier}.#{@bundle_identifier}"

  @doc """
  A throwaway, self-signed root certificate that the fixture's Attestation
  does not chain to — a substitute root for constructing the "untrusted
  root" rejection (the root is always an explicit parameter, precisely so
  a test can do this).
  """
  @spec untrusted_root() :: AppAttest.RootCertificate.der()
  def untrusted_root do
    :secp256r1
    |> X509.PrivateKey.new_ec()
    |> X509.Certificate.self_signed("/CN=Not Apple", template: :root_ca)
    |> X509.Certificate.to_der()
  end

  @doc """
  A freshly self-generated device key pair, standing in for a device's
  Secure Enclave App Attest key. No real Assertion is recorded (only the
  Attestation above is): the Spec's domain rule "Validation is trusted only
  once it has been proven against Attestations Apple actually issued"
  requires proof against real, Apple-issued data only for Attestations, so an
  Assertion's "genuine" scenario and its rejection fixtures are self-signed
  here instead, the same way `untrusted_root/0` self-signs a substitute
  root.
  """
  @spec device_key_pair() :: {X509.PrivateKey.t(), :public_key.public_key()}
  def device_key_pair do
    private_key = X509.PrivateKey.new_ec(:secp256r1)
    {private_key, X509.PublicKey.derive(private_key)}
  end

  @doc """
  A self-generated clientData value standing in for the request-specific
  data a real caller would hash and ask the device to sign (no real device
  Assertion is recorded, matching `device_key_pair/0` and `assertion/4`
  below).
  """
  @spec client_data() :: binary()
  def client_data, do: "self-generated-client-data"

  @doc """
  A self-generated, CBOR-encoded Assertion object for `counter`, `app_id`
  (`"<Team ID>.<bundle ID>"`) and `client_data`, signed by `private_key`
  over Apple's nonce: the SHA-256 of its own authenticator data
  (`authenticator_data/2`, the 37-byte prefix without attested credential
  data) concatenated with `client_data`'s SHA-256 hash. The nonce is
  computed here from Apple's documented construction, never with the
  library's own nonce function, so an accepted Assertion proves the
  library builds it the same way.

  Options make one field of the envelope wrong at a time. Each takes the
  CBOR value to put in that field as is (wrap a binary with `cbor_bytes/1`
  for a well-formed byte string), or `:omit` to leave the field out:

  * `:signature` - in place of the genuine signature.
  * `:authenticator_data` - in place of the genuine authenticator data.
  """
  @spec assertion(non_neg_integer(), String.t(), binary(), X509.PrivateKey.t(), keyword()) ::
          binary()
  def assertion(counter, app_id, client_data, private_key, opts \\ []) do
    auth_data = authenticator_data(app_id, counter: counter)
    signature = :public_key.sign(apple_nonce(auth_data, client_data), :sha256, private_key)

    %{}
    |> put_field("signature", Keyword.get(opts, :signature, cbor_bytes(signature)))
    |> put_field(
      "authenticatorData",
      Keyword.get(opts, :authenticator_data, cbor_bytes(auth_data))
    )
    |> CBOR.encode()
  end

  @doc """
  Authenticator data for `app_id`, in Apple's layout: the 37-byte prefix
  (SHA-256 of the App ID, one flags byte, a 4-byte big-endian Counter),
  followed by attested credential data (a 16-byte aaguid, a 2-byte
  credentialId length and the credentialId) when `:attested_credential` is
  given, as an Attestation carries it; an Assertion carries the prefix only.

  Options:

  * `:counter` - the Counter (default 0).
  * `:flags` - the flags byte (default 0).
  * `:attested_credential` - `{aaguid, credential_id}` (default: none).
  """
  @spec authenticator_data(String.t(), keyword()) :: binary()
  def authenticator_data(app_id, opts \\ []) do
    prefix =
      <<:crypto.hash(:sha256, app_id)::binary, Keyword.get(opts, :flags, 0),
        Keyword.get(opts, :counter, 0)::32-big>>

    case Keyword.get(opts, :attested_credential) do
      nil ->
        prefix

      {aaguid, credential_id} ->
        prefix <> aaguid <> <<byte_size(credential_id)::16>> <> credential_id
    end
  end

  @doc """
  An entirely self-generated `apple-appattest` Attestation (no real device
  involved), returned with what `AppAttest.Attestation.validate/6` needs to
  accept it:

  * `:attestation` - the CBOR-encoded Attestation object.
  * `:key_id` - base64 SHA-256 of the leaf's public key in X9.62
    uncompressed point format, as Apple's SDK derives it.
  * `:root` - the self-signed leaf itself, which doubles as the trusted
    root, so only what a test deliberately varies can make it fail.
  * `:app_id`, `:challenge` - the App ID and challenge it was built for.

  By default its authenticator data is consistent with `key_id`: Counter
  0, Apple's development aaguid and a credentialId equal to the Key ID.
  Apple's real Attestation cannot stand in for a wrong field there: its
  authData is signed over by the nonce, so altering it breaks the nonce
  check first and never reaches the check a test targets. The nonce is
  computed here from Apple's documented construction, never with the
  library's own nonce function. Options vary one field at a time:

  * `:counter` - the authenticator data's Counter (default 0).
  * `:aaguid` - the aaguid (default: Apple's development value).
  * `:credential_id` - the credentialId (default: the Key ID's bytes).
  * `:attested_credential_data` - `false` for only the 37-byte prefix, a
    structurally valid but malformed Attestation no genuine device would
    ever produce.

  And, one envelope field at a time, the CBOR value to put in that field
  as is (wrap a binary with `cbor_bytes/1` for a well-formed byte string),
  or `:omit` to leave it out:

  * `:fmt` - in place of `"apple-appattest"`.
  * `:att_stmt` - in place of the whole `attStmt` map.
  * `:x5c` - in place of the certificate chain.
  * `:receipt` - in place of the receipt (default: the byte string
    `"a-receipt"`).
  * `:auth_data` - in place of the authenticator data.
  """
  @spec self_generated_attestation(keyword()) :: %{
          attestation: binary(),
          key_id: String.t(),
          root: AppAttest.RootCertificate.der(),
          app_id: String.t(),
          challenge: binary()
        }
  def self_generated_attestation(opts \\ []) do
    app_id = Keyword.get(opts, :app_id, @self_generated_app_id)
    challenge = Keyword.get(opts, :challenge, @self_generated_challenge)

    private_key = X509.PrivateKey.new_ec(:secp256r1)
    {{:ECPoint, public_key_point}, _parameters} = X509.PublicKey.derive(private_key)
    key_id_bytes = :crypto.hash(:sha256, public_key_point)

    attested_credential =
      if Keyword.get(opts, :attested_credential_data, true) do
        {Keyword.get(opts, :aaguid, "appattestdevelop"),
         Keyword.get(opts, :credential_id, key_id_bytes)}
      end

    auth_data =
      authenticator_data(app_id,
        counter: Keyword.get(opts, :counter, 0),
        attested_credential: attested_credential
      )

    nonce_extension =
      {:Extension, @nonce_extension_oid, false,
       @nonce_extension_wrapper <> apple_nonce(auth_data, challenge)}

    leaf_der =
      private_key
      |> X509.Certificate.self_signed("/CN=Test Device",
        extensions: [apple_nonce: nonce_extension]
      )
      |> X509.Certificate.to_der()

    att_stmt =
      %{}
      |> put_field("x5c", Keyword.get(opts, :x5c, [cbor_bytes(leaf_der)]))
      |> put_field("receipt", Keyword.get(opts, :receipt, cbor_bytes("a-receipt")))

    attestation =
      %{}
      |> put_field("fmt", Keyword.get(opts, :fmt, "apple-appattest"))
      |> put_field("attStmt", Keyword.get(opts, :att_stmt, att_stmt))
      |> put_field("authData", Keyword.get(opts, :auth_data, cbor_bytes(auth_data)))
      |> CBOR.encode()

    %{
      attestation: attestation,
      key_id: Base.encode64(key_id_bytes),
      root: leaf_der,
      app_id: app_id,
      challenge: challenge
    }
  end

  @doc """
  `value` as a CBOR byte string, the way Apple encodes every binary field
  of an Attestation or Assertion: the `cbor` package encodes a plain
  binary as a CBOR *text* string instead.
  """
  @spec cbor_bytes(binary()) :: CBOR.Tag.t()
  def cbor_bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  @doc """
  `binary` with the byte at zero-based `position` flipped (XOR 0xFF), so
  it always differs from the original, whatever the original byte was.
  """
  @spec flip_byte(binary(), non_neg_integer()) :: binary()
  def flip_byte(binary, position) do
    <<before::binary-size(^position), byte, rest::binary>> = binary
    <<before::binary, Bitwise.bxor(byte, 0xFF), rest::binary>>
  end

  # Apple's nonce, from its documented construction ("Validating apps that
  # connect to your server", steps 2 and 3 of an Attestation, 2 of an
  # Assertion): SHA-256 of the authenticator data concatenated with the
  # SHA-256 of the challenge or clientData.
  defp apple_nonce(auth_data, client_data) do
    :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, client_data))
  end

  defp unwrap_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value

  defp put_field(map, _key, :omit), do: map
  defp put_field(map, key, value), do: Map.put(map, key, value)

  @doc """
  A throwaway root and leaf certificate pair standing in for a receipt's
  real chain to Apple Root CA - G3
  (`AppAttest.RootCertificate.apple_root_ca_g3/0`): `root` is the
  substitute trusted root a test passes to `AppAttest.Receipt.verify/2` or
  `AppAttest.RiskMetric.fetch/5` in place of the real one; `leaf` and
  `leaf_key` sign a receipt built by `receipt/2`. Issued from one another
  rather than self-signed like `untrusted_root/0`, because
  `AppAttest.Receipt` finds the signer
  among a receipt's own embedded certificates instead of assuming there is
  only one to check.
  """
  @spec risk_metric_chain() :: %{
          root: AppAttest.RootCertificate.der(),
          leaf: AppAttest.RootCertificate.der(),
          leaf_key: X509.PrivateKey.t()
        }
  def risk_metric_chain do
    root_key = X509.PrivateKey.new_ec(:secp256r1)

    root_cert =
      X509.Certificate.self_signed(root_key, "/CN=Test Receipt Root", template: :root_ca)

    leaf_key = X509.PrivateKey.new_ec(:secp256r1)

    leaf_cert =
      X509.Certificate.new(
        X509.PublicKey.derive(leaf_key),
        "/CN=Test Receipt Signer",
        root_cert,
        root_key
      )

    %{
      root: X509.Certificate.to_der(root_cert),
      leaf: X509.Certificate.to_der(leaf_cert),
      leaf_key: leaf_key
    }
  end

  @doc """
  A fresh DeviceCheck key fixture, standing in for a real key downloaded
  from the Apple Developer portal. Its DeviceCheck key identifier and Team
  ID are 10-character placeholders, the length Apple assigns both
  (`t:AppAttest.RiskMetric.device_check_key/0`'s own typedoc).
  """
  @spec device_check_key() :: AppAttest.RiskMetric.device_check_key()
  def device_check_key do
    %{
      key_id: "DEVCHECK01",
      team_id: "TEAMID1234",
      private_key: X509.PrivateKey.new_ec(:secp256r1)
    }
  end

  @doc """
  A self-signed CMS/PKCS#7 receipt carrying `risk_metric` in Apple's
  own field 17, and validity dates in its fields 19 and 21
  (`AppAttest.Receipt`'s own moduledoc), signed by `chain.leaf_key` over
  `chain.leaf` (`risk_metric_chain/0`). `receipt_not_before/0` and
  `receipt_expiration_time/0` are the two dates it carries.
  """
  @spec receipt(non_neg_integer(), %{leaf: binary(), leaf_key: X509.PrivateKey.t()}) :: binary()
  def receipt(risk_metric, chain) do
    receipt_with_attributes(chain, [
      {@receipt_type_field, "RECEIPT"},
      {@risk_metric_field, Integer.to_string(risk_metric)},
      {@not_before_field, DateTime.to_iso8601(@receipt_not_before)},
      {@expiration_time_field, DateTime.to_iso8601(@receipt_expiration_time)}
    ])
  end

  @doc "The Not Before date (Apple's field 19) every `receipt/2` carries."
  @spec receipt_not_before() :: DateTime.t()
  def receipt_not_before, do: @receipt_not_before

  @doc "The Expiration Time (Apple's field 21) every `receipt/2` carries."
  @spec receipt_expiration_time() :: DateTime.t()
  def receipt_expiration_time, do: @receipt_expiration_time

  @doc """
  A self-signed CMS/PKCS#7 receipt carrying exactly `attributes`, each a
  `{field number, value}` pair in Apple's own receipt attribute list — what
  `receipt/2` builds a well-formed receipt out of, and what a test
  constructs a deliberately malformed one out of, one wrong field at a time.

  No PKCS#7/CMS-signing Hex package exists to build this with, and shelling
  out to `openssl cms` would need an OpenSSL the stock macOS LibreSSL does
  not provide. `:public_key`'s own `der_encode/2` dispatches `'ContentInfo'`
  to the same compiled-in RFC 5652 ASN.1 module that `AppAttest.Receipt`
  already decodes receipts with, so the envelope is built with that instead
  — no external tool, no temporary files.
  """
  @spec receipt_with_attributes(%{leaf: binary(), leaf_key: X509.PrivateKey.t()}, [
          {non_neg_integer(), binary()}
        ]) :: binary()
  def receipt_with_attributes(chain, attributes) do
    receipt_with_payload(
      chain,
      der_set(Enum.map(attributes, fn {field, value} -> der_attribute(field, value) end))
    )
  end

  @doc """
  A self-signed CMS/PKCS#7 receipt whose signed content is exactly
  `payload` — the envelope `receipt_with_attributes/2` builds, with the
  attribute list left to the caller, so a test can put a payload that is not
  a well-formed attribute list at all inside an otherwise genuine,
  correctly signed receipt.
  """
  @spec receipt_with_payload(%{leaf: binary(), leaf_key: X509.PrivateKey.t()}, binary()) ::
          binary()
  def receipt_with_payload(%{leaf: leaf_der, leaf_key: leaf_key}, payload) do
    leaf = X509.Certificate.from_der!(leaf_der)
    digest_algorithm = {:DigestAlgorithmIdentifier, @sha256_oid, :asn1_NOVALUE}

    signer_info =
      {:SignerInfo, :v1,
       {:issuerAndSerialNumber,
        {:IssuerAndSerialNumber, X509.Certificate.issuer(leaf), X509.Certificate.serial(leaf)}},
       digest_algorithm, :asn1_NOVALUE,
       {:SignatureAlgorithmIdentifier, @ecdsa_with_sha256_oid, :asn1_NOVALUE},
       :public_key.sign(payload, :sha256, leaf_key), :asn1_NOVALUE}

    signed_data =
      {:SignedData, :v1, [digest_algorithm], {:EncapsulatedContentInfo, @data_oid, payload},
       [certificate: :public_key.der_decode(:Certificate, leaf_der)], :asn1_NOVALUE,
       [signer_info]}

    :public_key.der_encode(:ContentInfo, {:ContentInfo, @signed_data_oid, signed_data})
  end

  defp der_attribute(field, value) do
    der_sequence(der_integer(field) <> der_integer(1) <> der_octet_string(value))
  end

  defp der_set(elements), do: der_tlv(0x31, Enum.join(elements))
  defp der_sequence(content), do: der_tlv(0x30, content)
  defp der_octet_string(value), do: der_tlv(0x04, value)

  defp der_integer(value) do
    bytes = :binary.encode_unsigned(value)
    # DER integers are signed: a value whose top bit is already set needs a
    # leading zero byte so it is not read back as negative.
    bytes = if :binary.first(bytes) >= 0x80, do: <<0>> <> bytes, else: bytes
    der_tlv(0x02, bytes)
  end

  defp der_tlv(tag, content), do: <<tag>> <> der_length(byte_size(content)) <> content

  # Short form only: every value this module builds is a handful of bytes.
  defp der_length(length) when length < 128, do: <<length>>
end
