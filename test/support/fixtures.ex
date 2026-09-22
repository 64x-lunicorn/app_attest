defmodule AppAttest.Fixtures do
  @moduledoc """
  A real, Apple-issued development Attestation, reused under MIT license
  (notice kept, see the repository's own `NOTICE` file) from
  `uebelack/node-app-attest`'s `test/fixtures/attestation-development.json`
  (https://github.com/uebelack/node-app-attest).

  The Spec's own domain rule 6 (#166) — validation is trusted only once
  proven against Attestations Apple actually issued, not only against
  self-generated data — is why this ticket (#168) proves its "genuine
  Attestation is accepted" scenario against these real bytes rather than
  self-generated ones. The three rejection scenarios reuse the very same
  bytes with one input deliberately wrong at a time (wrong challenge, wrong
  App ID, wrong root), so each is proven to fail for that one specific
  reason (Spec domain rule 7) without needing separate self-generated
  fixtures for them.
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
    Enum.map(x5c, fn %CBOR.Tag{tag: :bytes, value: der} -> der end)
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
end
