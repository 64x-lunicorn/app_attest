defmodule AppAttest.Attestation do
  @moduledoc """
  Validates a device's App Attest Attestation (Spec #166, architecture
  #174): its certificate chain against Apple's own App Attest root, its
  nonce against the expected challenge, and its App ID hash against the
  expected app.

  `app_attest` holds no device state itself (CLAUDE.md, Corridor ADR
  0006, #174): `validate/5` returns the device's public key, start Counter
  and App Attest environment for the caller to persist; it persists
  nothing on its own.
  """

  alias AppAttest.{AuthenticatorData, Envelope, RootCertificate}

  @typedoc "The result of a successful Attestation: what the caller now persists."
  @type attested :: %{
          public_key: :public_key.public_key(),
          counter: non_neg_integer(),
          environment: AuthenticatorData.environment()
        }

  @typedoc """
  Every reason `validate/5` rejects an Attestation. A malformed Attestation
  is rejected with one of these, never by raising (#212): the whole point of
  this library is to distrust its own input.

  * `:invalid_attestation` - `attestation_object` is not an
    `apple-appattest` attestation object: not well-formed CBOR at all, a
    different `fmt`, a missing `attStmt` or `authData`, an `authData` that
    is not a CBOR byte string, an empty or missing `x5c` certificate chain,
    or junk in place of a certificate. Which CBOR decoding failure it was
    is deliberately not told apart, so no atom of the `cbor` package
    reaches a caller (#10).
  * `:untrusted_root` - the certificate chain does not lead to `root`.
  * `:nonce_mismatch` - the nonce does not match `challenge`.
  * `:invalid_authenticator_data` - the authenticator data is truncated
    (`AppAttest.AuthenticatorData.parse/1`).
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:unrecognized_environment` - the attested credential data's aaguid is
    neither Apple's development nor production value, or missing entirely.
  """
  @type rejection ::
          :invalid_attestation
          | :untrusted_root
          | :nonce_mismatch
          | :invalid_authenticator_data
          | :app_id_mismatch
          | :unrecognized_environment

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
  `Application` config). `key_id` (the app-supplied key identifier, base64)
  is part of this seam's agreed shape (architecture #174) but not itself
  checked by ticket #168's scope.

  Returns `{:ok, attested}` with the device's public key, start Counter and
  App Attest environment (`:development` or `:production`, read from the
  attestation's own `aaguid`, #170) for the caller to persist, or
  `{:error, rejection}`.
  """
  @spec validate(binary(), String.t(), binary(), String.t(), RootCertificate.der()) ::
          {:ok, attested()} | {:error, rejection()}
  def validate(attestation_object, _key_id, challenge, app_id, root) do
    with {:ok, %{auth_data: auth_data, chain: chain}} <-
           Envelope.decode_attestation(attestation_object),
         {:ok, leaf} <- leaf_certificate(chain),
         :ok <- check_trusted_chain(root, chain),
         :ok <- check_nonce(leaf, auth_data, challenge),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id),
         {:ok, environment} <- check_environment(authenticator_data.aaguid) do
      {:ok,
       %{
         public_key: X509.Certificate.public_key(leaf),
         counter: authenticator_data.counter,
         environment: environment
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

  defp check_environment(aaguid) do
    case AuthenticatorData.environment(aaguid) do
      environment when environment in [:development, :production] -> {:ok, environment}
      {:error, :unrecognized_environment} = error -> error
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
