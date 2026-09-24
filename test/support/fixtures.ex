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
    AppAttest.Attestation.unwrap_chain(x5c)
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
  hash, per Apple's own nonce construction (`AppAttest.Assertion`'s own
  `check_signature/4`) — the same 37-byte prefix shape
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
    client_data_hash = :crypto.hash(:sha256, client_data)
    nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
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
  downloaded from the Apple Developer portal.
  """
  @spec device_check_key() :: AppAttest.RiskMetric.device_check_key()
  def device_check_key do
    %{
      key_id: "DEVICECHECKKEY01",
      team_id: "TEAMID12345",
      private_key: X509.PrivateKey.new_ec(:secp256r1)
    }
  end

  @doc """
  A self-signed CMS/PKCS#7 receipt (#171) carrying `risk_metric` in
  Apple's own field 17 (`AppAttest.RiskMetric`'s own moduledoc), signed by
  `chain.leaf_key` over `chain.leaf` (`risk_metric_chain/0`).

  No PKCS#7/CMS-signing Hex package exists to build this with, so this
  shells out to the system `openssl cms` — the same tool this ticket's own
  implementation used to confirm `AppAttest.RiskMetric`'s parsing against a
  standards-compliant signature, not only against itself. `AppAttest.
  RiskMetric` itself only ever *decodes* a receipt (Apple's own job is to
  build one), so it has no matching encoder of its own to reuse here.
  """
  @spec receipt(non_neg_integer(), %{leaf: binary(), leaf_key: X509.PrivateKey.t()}) :: binary()
  def receipt(risk_metric, %{leaf: leaf_der, leaf_key: leaf_key}) do
    id = System.unique_integer([:positive])
    tmp_path = fn suffix -> Path.join(System.tmp_dir!(), "app_attest_receipt_#{id}_#{suffix}") end

    payload_path = tmp_path.("payload.der")
    leaf_path = tmp_path.("leaf.pem")
    key_path = tmp_path.("key.pem")
    out_path = tmp_path.("receipt.der")

    File.write!(payload_path, receipt_payload(risk_metric))
    File.write!(leaf_path, leaf_der |> X509.Certificate.from_der!() |> X509.Certificate.to_pem())
    File.write!(key_path, X509.PrivateKey.to_pem(leaf_key))

    {_output, 0} =
      System.cmd("openssl", [
        "cms",
        "-sign",
        "-in",
        payload_path,
        "-inform",
        "DER",
        "-outform",
        "DER",
        "-binary",
        "-noattr",
        "-signer",
        leaf_path,
        "-inkey",
        key_path,
        "-nodetach",
        "-out",
        out_path
      ])

    receipt = File.read!(out_path)
    Enum.each([payload_path, leaf_path, key_path, out_path], &File.rm/1)
    receipt
  end

  # Apple's own receipt payload, undocumented by any ASN.1 module:
  # `SET OF SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }`
  # (`AppAttest.RiskMetric`'s own moduledoc). Field 6 ("Receipt Type") is
  # always "RECEIPT" for a receipt fetched this way, never "ATTEST" (the
  # value the one that accompanies an Attestation object carries).
  defp receipt_payload(risk_metric) do
    der_set([
      der_attribute(6, "RECEIPT"),
      der_attribute(17, Integer.to_string(risk_metric))
    ])
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
