defmodule AppAttest.Assertion do
  @moduledoc """
  Validates a device's App Attest Assertion (Spec #166, architecture #174):
  its signature against the device's already-attested public key, its App
  ID hash against the expected app, and its Counter against the device's
  last stored Counter, so a captured Assertion cannot be replayed.

  `app_attest` holds no device state itself (CLAUDE.md, Corridor ADR 0006,
  #174): `validate/4` takes the caller's stored public key and Counter as
  input and returns the new Counter for the caller to persist; it persists
  nothing on its own.
  """

  alias AppAttest.AuthenticatorData

  @typedoc """
  * `:invalid_signature` - the signature does not match `public_key`.
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:counter_not_increasing` - the Counter is not strictly greater than `stored_counter`.
  """
  @type rejection :: :invalid_signature | :app_id_mismatch | :counter_not_increasing

  @doc """
  Validates `assertion_object` — the raw, CBOR-encoded assertion Apple's SDK
  produces — against `app_id` (`"<Team ID>.<bundle ID>"`) and the device's
  already-attested `public_key` and `stored_counter` (ticket #168's result,
  persisted by the caller).

  Returns `{:ok, new_counter}` with the assertion's own Counter, for the
  caller to persist in place of `stored_counter`, or `{:error, rejection}`.
  """
  @spec validate(binary(), String.t(), :public_key.public_key(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, rejection()}
  def validate(assertion_object, app_id, public_key, stored_counter) do
    with {:ok, decoded, _rest} <- CBOR.decode(assertion_object),
         %{"signature" => signature_tag, "authenticatorData" => auth_data_tag} = decoded,
         signature = AuthenticatorData.unwrap_bytes(signature_tag),
         auth_data = AuthenticatorData.unwrap_bytes(auth_data_tag),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- check_signature(auth_data, signature, public_key),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id) do
      check_counter(authenticator_data, stored_counter)
    end
  end

  defp check_signature(auth_data, signature, public_key) do
    if :public_key.verify(auth_data, :sha256, signature, public_key) do
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
