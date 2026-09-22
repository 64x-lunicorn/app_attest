defmodule AppAttest.Assertion do
  @moduledoc """
  Validates a device's App Attest Assertion (Spec #166, architecture #174):
  its signature against the device's already-attested public key and the
  caller's `client_data` for this request, its App ID hash against the
  expected app, and its Counter against the device's last stored Counter,
  so a captured Assertion cannot be replayed, nor reused for a different
  request than the one it was signed for.

  `app_attest` holds no device state itself (CLAUDE.md, Corridor ADR 0006,
  #174): `validate/5` takes the caller's stored public key and Counter as
  input and returns the new Counter for the caller to persist; it persists
  nothing on its own.
  """

  alias AppAttest.AuthenticatorData

  @typedoc """
  * `:invalid_signature` - the signature does not match `public_key` and
    `client_data`.
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:counter_not_increasing` - the Counter is not strictly greater than `stored_counter`.
  """
  @type rejection :: :invalid_signature | :app_id_mismatch | :counter_not_increasing

  @doc """
  Validates `assertion_object` — the raw, CBOR-encoded assertion Apple's SDK
  produces — against `client_data` (the request-specific data the caller
  asked the device to sign, typically embedding a fresh server challenge),
  `app_id` (`"<Team ID>.<bundle ID>"`) and the device's already-attested
  `public_key` and `stored_counter` (ticket #168's result, persisted by the
  caller).

  Apple's own on-device API signs every Assertion over `authenticatorData`
  concatenated with the SHA-256 hash of `client_data`, never
  `authenticatorData` alone, so a genuine Assertion only verifies against
  the same `client_data` the device was asked to sign for that request.

  Returns `{:ok, new_counter}` with the assertion's own Counter, for the
  caller to persist in place of `stored_counter`, or `{:error, rejection}`.
  """
  @spec validate(binary(), binary(), String.t(), :public_key.public_key(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, rejection()}
  def validate(assertion_object, client_data, app_id, public_key, stored_counter) do
    with {:ok, decoded, _rest} <- CBOR.decode(assertion_object),
         %{"signature" => signature_tag, "authenticatorData" => auth_data_tag} = decoded,
         signature = AuthenticatorData.unwrap_bytes(signature_tag),
         auth_data = AuthenticatorData.unwrap_bytes(auth_data_tag),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- check_signature(auth_data, client_data, signature, public_key),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id) do
      check_counter(authenticator_data, stored_counter)
    end
  end

  # Apple's own nonce construction (confirmed against "Validating apps that
  # connect to your server" and architecture #174's reference
  # implementations, takimoto3/app-attest and uebelack/node-app-attest,
  # which both build and verify it this same way): hash `client_data` to
  # get clientDataHash, append it to the raw authenticator data, and hash
  # the result again to get the nonce the signature actually covers.
  defp check_signature(auth_data, client_data, signature, public_key) do
    client_data_hash = :crypto.hash(:sha256, client_data)
    nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)

    if :public_key.verify(nonce, :sha256, signature, public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp check_counter(%AuthenticatorData{counter: counter}, stored_counter) do
    if counter > stored_counter do
      {:ok, counter}
    else
      {:error, :counter_not_increasing}
    end
  end
end
