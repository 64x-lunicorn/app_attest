defmodule AppAttest.Assertion do
  @moduledoc """
  Validates a device's App Attest Assertion (Spec #166, architecture #174):
  its signature against the device's already-attested public key and the
  caller's `client_data` for this request, its App ID hash against the
  expected app, its Counter against the device's last stored Counter, so a
  captured Assertion cannot be replayed, nor reused for a different request
  than the one it was signed for, and its claimed environment against the
  one the device was attested in (#170).

  `app_attest` holds no device state itself (CLAUDE.md, Corridor ADR 0006,
  #174): `validate/7` takes the caller's stored public key, Counter and
  environment as input and returns the new Counter for the caller to
  persist; it persists nothing on its own.
  """

  alias AppAttest.AuthenticatorData

  @typedoc """
  Every reason `validate/7` rejects an Assertion. A malformed Assertion is
  rejected with one of these, never by raising (#212): the whole point of
  this library is to distrust its own input.

  * `:environment_mismatch` - `expected_environment` does not match `stored_environment`.
  * `t:AppAttest.AuthenticatorData.cbor_error/0` - `assertion_object` is not
    well-formed CBOR at all.
  * `:invalid_assertion` - it decodes, but is not an assertion object: a
    missing `signature` or `authenticatorData`, or one of the two not a
    CBOR byte string.
  * `:invalid_authenticator_data` - the authenticator data is truncated
    (`AppAttest.AuthenticatorData.parse/1`).
  * `:invalid_signature` - the signature does not match `public_key` and
    `client_data`.
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:counter_not_increasing` - the Counter is not strictly greater than `stored_counter`.
  """
  @type rejection ::
          :environment_mismatch
          | AuthenticatorData.cbor_error()
          | :invalid_assertion
          | :invalid_authenticator_data
          | :invalid_signature
          | :app_id_mismatch
          | :counter_not_increasing

  @doc """
  Validates `assertion_object` — the raw, CBOR-encoded assertion Apple's SDK
  produces — against `client_data` (the request-specific data the caller
  asked the device to sign, typically embedding a fresh server challenge),
  `app_id` (`"<Team ID>.<bundle ID>"`) and the device's already-attested
  `public_key`, `stored_counter` and `stored_environment` (ticket #168's
  result, persisted by the caller).

  Apple's own on-device API signs every Assertion over `authenticatorData`
  concatenated with the SHA-256 hash of `client_data`, never
  `authenticatorData` alone, so a genuine Assertion only verifies against
  the same `client_data` the device was asked to sign for that request.

  An Assertion carries no environment bytes of its own, so `expected_environment`
  is the environment the caller expects for this request (#170); it is
  compared against `stored_environment`, never read off the assertion
  itself.

  Returns `{:ok, new_counter}` with the assertion's own Counter, for the
  caller to persist in place of `stored_counter`, or `{:error, rejection}`.
  """
  @spec validate(
          binary(),
          binary(),
          String.t(),
          :public_key.public_key(),
          non_neg_integer(),
          AuthenticatorData.environment(),
          AuthenticatorData.environment()
        ) :: {:ok, non_neg_integer()} | {:error, rejection()}
  def validate(
        assertion_object,
        client_data,
        app_id,
        public_key,
        stored_counter,
        stored_environment,
        expected_environment
      ) do
    with :ok <- check_environment(stored_environment, expected_environment),
         {:ok, decoded, _rest} <- CBOR.decode(assertion_object),
         {:ok, signature, auth_data} <- unwrap_assertion(decoded),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- check_signature(auth_data, client_data, signature, public_key),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id) do
      check_counter(authenticator_data, stored_counter)
    end
  end

  # Both fields a genuine Assertion object carries, taken apart in one
  # place: anything else is not an assertion object and is rejected rather
  # than raising (#212, the shape `AppAttest.RiskMetric`'s own parsers
  # already use for a Receipt).
  defp unwrap_assertion(%{"signature" => signature_tag, "authenticatorData" => auth_data_tag}) do
    with {:ok, signature} <- AuthenticatorData.unwrap_bytes(signature_tag),
         {:ok, auth_data} <- AuthenticatorData.unwrap_bytes(auth_data_tag) do
      {:ok, signature, auth_data}
    else
      :error -> {:error, :invalid_assertion}
    end
  end

  defp unwrap_assertion(_not_an_assertion), do: {:error, :invalid_assertion}

  defp check_environment(stored_environment, expected_environment) do
    if stored_environment == expected_environment do
      :ok
    else
      {:error, :environment_mismatch}
    end
  end

  # An Assertion's signature covers Apple's own nonce construction, built
  # by the one shared `AppAttest.AuthenticatorData.nonce/2` an Attestation's
  # own nonce check uses too (#212), never `auth_data` alone.
  defp check_signature(auth_data, client_data, signature, public_key) do
    nonce = AuthenticatorData.nonce(auth_data, client_data)

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
