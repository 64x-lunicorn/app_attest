defmodule AppAttest.Fixtures do
  @moduledoc """
  A real, Apple-issued development Attestation, reused under MIT license
  (notice kept, see the repository's own `NOTICE` file) from
  `uebelack/node-app-attest`'s `test/fixtures/attestation-development.json`
  (https://github.com/uebelack/node-app-attest); plus self-generated device
  key pairs and Assertions (#169).

  The Spec's own domain rule 6 (#166) — validation is trusted only once
  proven against Attestations Apple actually issued, not only against
  self-generated data — is why this ticket (#168) proves its "genuine
  Attestation is accepted" scenario against these real bytes rather than
  self-generated ones. The three rejection scenarios reuse the very same
  bytes with one input deliberately wrong at a time (wrong challenge, wrong
  App ID, wrong root), so each is proven to fail for that one specific
  reason (Spec domain rule 7) without needing separate self-generated
  fixtures for them. Domain rule 6 names Attestations specifically: no real
  device Assertion is recorded, so `device_key_pair/0` and `assertion/3`
  build self-signed Assertion data instead (#169's own implementation
  notes).
  """

  @fixture_path Path.join(__DIR__, "fixtures/attestation-development.json")
  @external_resource @fixture_path

  @fixture @fixture_path |> File.read!() |> :json.decode()

  # From the same reference repository's test suite, alongside the fixture
  # file: https://github.com/uebelack/node-app-attest/blob/main/test/verifyAttestation.test.js
  @team_identifier "V8H6LQ9448"
  @bundle_identifier "io.uebelacker.AppAttestExample"

  # Apple's own receipt attribute numbers ("Assessing fraud risk", the same
  # table `AppAttest.RiskMetric` reads). Field 6 ("Receipt Type") is always
  # "RECEIPT" for a receipt fetched from the risk-metric endpoint, never
  # "ATTEST" (the value the one accompanying an Attestation object carries).
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
  DER-encoded, decoded straight out of the CBOR attestation object.
  """
  @spec certificate_chain() :: [AppAttest.RootCertificate.der(), ...]
  def certificate_chain do
    {:ok, %{"attStmt" => %{"x5c" => x5c}}, _rest} = CBOR.decode(attestation())
    {:ok, chain} = AppAttest.Attestation.unwrap_chain(x5c)
    chain
  end

  @doc "This Attestation's App ID: `\"<Team ID>.<bundle ID>\"`."
  @spec app_id() :: String.t()
  def app_id, do: "#{@team_identifier}.#{@bundle_identifier}"

  @doc """
  A throwaway, self-signed root certificate that the fixture's Attestation
  does not chain to — a substitute root for constructing the "untrusted
  root" rejection (architecture #174: the root is always an explicit
  parameter, precisely so a test can do this).
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
  Secure Enclave App Attest key (#169). No real Assertion is recorded (only
  the Attestation above is): the Spec's own domain rule 6 (#166) requires
  proof against real, Apple-issued data only for Attestations, so an
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
  data a real caller would hash and ask the device to sign (follow-up to
  #169; no real device Assertion is recorded, matching `device_key_pair/0`
  and `assertion/4` below).
  """
  @spec client_data() :: binary()
  def client_data, do: "self-generated-client-data"

  @doc """
  A self-generated, CBOR-encoded Assertion object for `counter`, `app_id`
  (`"<Team ID>.<bundle ID>"`) and `client_data`, signed by `private_key`
  over its own authenticator data concatenated with `client_data`'s SHA-256
  hash, per Apple's own nonce construction
  (`AppAttest.AuthenticatorData.nonce/2`, the one shared function both
  `AppAttest.Attestation` and `AppAttest.Assertion` build it with) — the
  same 37-byte prefix shape
  `AppAttest.AuthenticatorData.parse/1` already parses for an Assertion (no
  attested credential data).

  Mirrors `attestation/0`'s own "wrong App ID hash" pattern: build one fixed
  fixture, then vary the *expected* app ID or client data passed to
  `validate/5` to construct a mismatch, rather than varying the fixture
  itself.

  Both the signature and the authenticator data are wrapped in
  `%CBOR.Tag{tag: :bytes}` before encoding, so they decode back the same
  way a real Apple-issued Assertion's fields do (confirmed against the
  `attestation-development.json` fixture's own `authData`): plain
  `CBOR.encode/1` of a raw binary produces a CBOR *text* string instead.
  """
  @spec assertion(non_neg_integer(), String.t(), binary(), X509.PrivateKey.t()) :: binary()
  def assertion(counter, app_id, client_data, private_key) do
    auth_data = <<:crypto.hash(:sha256, app_id)::binary, 0, counter::32-big>>
    nonce = AppAttest.AuthenticatorData.nonce(auth_data, client_data)
    signature = :public_key.sign(nonce, :sha256, private_key)

    CBOR.encode(%{
      "signature" => %CBOR.Tag{tag: :bytes, value: signature},
      "authenticatorData" => %CBOR.Tag{tag: :bytes, value: auth_data}
    })
  end

  @doc """
  A throwaway root and leaf certificate pair standing in for a receipt's
  real chain to Apple's own "Apple Root CA - G3"
  (`AppAttest.RootCertificate.apple_root_ca_g3/0`, #171): `root` is the
  substitute trusted root a test passes to `AppAttest.RiskMetric.fetch/5`
  in place of the real one; `leaf` and `leaf_key` sign a receipt built by
  `receipt/2`. Issued from one another rather than self-signed like
  `untrusted_root/0`, because `AppAttest.RiskMetric` finds the signer
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
  A fresh DeviceCheck key fixture (#171), standing in for a real key
  downloaded from the Apple Developer portal. Key ID and Team ID are
  10-character placeholders, the length Apple assigns both
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
  The receipt embedded in the fixture Attestation's own `attStmt.receipt`:
  a real, Apple-issued receipt, but one issued to `uebelack/node-app-attest`'s
  own team and long expired, so Apple answers a risk-metric request carrying
  it with an error rather than a new receipt
  (`AppAttest.RiskMetricAppleTest`).
  """
  @spec attestation_receipt() :: binary()
  def attestation_receipt do
    {:ok, %{"attStmt" => %{"receipt" => %CBOR.Tag{tag: :bytes, value: receipt}}}, _rest} =
      CBOR.decode(attestation())

    receipt
  end

  @doc """
  A self-signed CMS/PKCS#7 receipt (#171) carrying `risk_metric` in Apple's
  own field 17, and validity dates in its fields 19 and 21
  (`AppAttest.RiskMetric`'s own moduledoc), signed by `chain.leaf_key` over
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
  to the same compiled-in RFC 5652 ASN.1 module that `AppAttest.RiskMetric`
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
