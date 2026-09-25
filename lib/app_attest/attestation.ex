defmodule AppAttest.Attestation do
  @moduledoc """
  Validates a device's App Attest Attestation (Spec #166, architecture
  #174): its certificate chain against Apple's own App Attest root, its
  nonce against the expected challenge, its public key and credential ID
  against the app-supplied key identifier, its App ID hash against the
  expected app, its start Counter of 0 (#13), and its environment against
  the one the caller expects (#211).

  `app_attest` holds no device state itself (CLAUDE.md, Corridor ADR
  0006, #174): `validate/6` returns an `AppAttest.Device` with the
  device's public key, start Counter, App Attest environment and receipt
  for the caller to persist; it persists nothing on its own.
  """

  alias AppAttest.{AuthenticatorData, Device, Envelope, RootCertificate}

  @typedoc """
  Every reason `validate/6` rejects an Attestation. A malformed Attestation
  is rejected with one of these, never by raising (#212): the whole point of
  this library is to distrust its own input.

  * `:invalid_attestation` - `attestation_object` is not an
    `apple-appattest` attestation object: not well-formed CBOR at all, a
    different `fmt`, a missing `attStmt` or `authData`, an `authData` that
    is not a CBOR byte string, an empty or missing `x5c` certificate chain,
    junk in place of a certificate, or a missing `receipt` or one that is
    not a CBOR byte string (#11). Which CBOR decoding failure it was
    is deliberately not told apart, so no atom of the `cbor` package
    reaches a caller (#10).
  * `:untrusted_root` - the certificate chain does not lead to `root`.
  * `:nonce_mismatch` - the nonce does not match `challenge`.
  * `:key_id_mismatch` - `key_id` does not identify this Attestation's key:
    the SHA-256 of the credential certificate's public key, or the
    authenticator data's credentialId, differs from it, or `key_id` is not
    base64 at all (#13). A `key_id` that does not decode is one more key
    identifier that is not this key's, so it is not told apart.
  * `:invalid_authenticator_data` - the authenticator data is truncated
    (`AppAttest.AuthenticatorData.parse/1`).
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:counter_not_zero` - the authenticator data's Counter is not 0, the
    value every freshly attested key starts at (#13).
  * `:unrecognized_environment` - the attested credential data's aaguid is
    neither Apple's development nor production value, or missing entirely.
  * `:environment_mismatch` - the environment the aaguid yields is not
    `expected_environment` (#211).
  """
  @type rejection ::
          :invalid_attestation
          | :untrusted_root
          | :nonce_mismatch
          | :key_id_mismatch
          | :invalid_authenticator_data
          | :app_id_mismatch
          | :counter_not_zero
          | :unrecognized_environment
          | :environment_mismatch

  # Apple's own extension OID for the nonce, carried in the credential
  # certificate (credCert): a DER SEQUENCE containing one element, a
  # context-tag [1] wrapping an OCTET STRING of the 32-byte nonce. All
  # three lengths are fixed (the nonce is always a SHA-256 digest), so the
  # wrapper is always this same 6 bytes.
  @nonce_extension_oid {1, 2, 840, 113_635, 100, 8, 2}
  @nonce_extension_wrapper_size 6

  @doc """
  Validates `attestation_object` — the raw, CBOR-encoded attestation Apple's
  SDK produces — against `challenge` (the one-time server challenge the
  device attested), `app_id` (`"<Team ID>.<bundle ID>"`) and `root` (Apple's
  App Attest root, or a substitute — `AppAttest.RootCertificate`, never
  `Application` config), and binds it to `key_id`, the key identifier the
  app got from `DCAppAttestService.generateKey`, base64-encoded as Apple's
  SDK returns it (#13), and to `expected_environment`, the App Attest
  environment the caller expects for this request (#211).

  The checks run in the order Apple's "Validating apps that connect to your
  server" lists them: the certificate chain (step 1), the nonce (2-4), the
  SHA-256 of the credential certificate's public key in X9.62 uncompressed
  point format against `key_id` (5), the App ID hash (6), a Counter of 0
  (7), the aaguid's environment against `expected_environment` (8) and the
  credentialId against `key_id` (9). The first failing check decides the
  rejection. A development Attestation is never accepted where a
  production one is expected, or the reverse, the way
  `AppAttest.Assertion.validate/5` already rejects an Assertion.

  Returns `{:ok, device}`, an `AppAttest.Device` with the device's public
  key, start Counter, App Attest environment (`:development` or
  `:production`, read from the attestation's own `aaguid`, #170, and so
  always `expected_environment`) and the receipt the Attestation carried
  in `attStmt.receipt` (the one the first `AppAttest.RiskMetric.fetch/5`
  sends, #11) for the caller to persist, or `{:error, rejection}`.
  """
  @spec validate(
          binary(),
          String.t(),
          binary(),
          String.t(),
          RootCertificate.der(),
          AuthenticatorData.environment()
        ) :: {:ok, Device.t()} | {:error, rejection()}
  def validate(attestation_object, key_id, challenge, app_id, root, expected_environment) do
    with {:ok, %{auth_data: auth_data, chain: chain, receipt: receipt}} <-
           Envelope.decode_attestation(attestation_object),
         {:ok, leaf} <- leaf_certificate(chain),
         :ok <- check_trusted_chain(root, chain),
         :ok <- check_nonce(leaf, auth_data, challenge),
         {:ok, key_id_bytes} <- check_public_key_hash(leaf, key_id),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id),
         :ok <- check_counter(authenticator_data.counter),
         {:ok, environment} <-
           check_environment(authenticator_data.aaguid, expected_environment),
         :ok <- check_credential_id(authenticator_data.credential_id, key_id_bytes) do
      {:ok,
       %Device{
         public_key: X509.Certificate.public_key(leaf),
         counter: authenticator_data.counter,
         environment: environment,
         receipt: receipt
       }}
    end
  end

  defp leaf_certificate([leaf_der | _rest_of_chain]) do
    case X509.Certificate.from_der(leaf_der) do
      {:ok, leaf} -> {:ok, leaf}
      {:error, _malformed} -> {:error, :invalid_attestation}
    end
  end

  defp check_trusted_chain(root, chain) do
    if RootCertificate.trusted?(root, chain), do: :ok, else: {:error, :untrusted_root}
  end

  # Apple's step 5: the key identifier is the SHA-256 of the credential
  # certificate's public key in X9.62 uncompressed point format
  # (0x04 || X || Y), which is exactly the `ECPoint` the certificate's
  # SubjectPublicKeyInfo carries. Returns the decoded key identifier for
  # step 9 to compare the credentialId against.
  defp check_public_key_hash(leaf, key_id) do
    with {:ok, key_id_bytes} <- decode_key_id(key_id),
         {{:ECPoint, point}, _parameters} <- X509.Certificate.public_key(leaf),
         true <- :crypto.hash(:sha256, point) == key_id_bytes do
      {:ok, key_id_bytes}
    else
      _not_this_key -> {:error, :key_id_mismatch}
    end
  end

  defp decode_key_id(key_id) when is_binary(key_id), do: Base.decode64(key_id)
  defp decode_key_id(_not_a_string), do: :error

  defp check_counter(0), do: :ok
  defp check_counter(_not_zero), do: {:error, :counter_not_zero}

  defp check_credential_id(key_id_bytes, key_id_bytes), do: :ok
  defp check_credential_id(_credential_id, _key_id_bytes), do: {:error, :key_id_mismatch}

  defp check_environment(aaguid, expected_environment) do
    case AuthenticatorData.environment(aaguid) do
      ^expected_environment ->
        {:ok, expected_environment}

      environment when environment in [:development, :production] ->
        {:error, :environment_mismatch}

      {:error, :unrecognized_environment} = error ->
        error
    end
  end

  defp check_nonce(leaf, auth_data, challenge) do
    expected_nonce = AuthenticatorData.nonce(auth_data, challenge)

    with {:Extension, _oid, _critical, extension_value} <-
           X509.Certificate.extension(leaf, @nonce_extension_oid),
         <<_wrapper::binary-size(@nonce_extension_wrapper_size), nonce::binary>> <-
           extension_value,
         true <- nonce == expected_nonce do
      :ok
    else
      _no_or_mismatched_nonce -> {:error, :nonce_mismatch}
    end
  end
end
