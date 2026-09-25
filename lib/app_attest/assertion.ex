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
  #174): `validate/5` takes the caller's stored `AppAttest.Device` as input
  and returns it with the Counter moved on, for the caller to persist; it
  persists nothing on its own.
  """

  alias AppAttest.{AuthenticatorData, Device, Envelope}

  @typedoc """
  Every reason `validate/5` rejects an Assertion. A malformed Assertion is
  rejected with one of these, never by raising (#212): the whole point of
  this library is to distrust its own input.

  * `:environment_mismatch` - `expected_environment` does not match the
    Device's `environment`.
  * `:invalid_assertion` - `assertion_object` is not an assertion object:
    not well-formed CBOR at all, a missing `signature` or
    `authenticatorData`, or one of the two not a CBOR byte string. Which
    CBOR decoding failure it was is deliberately not told apart, so no atom
    of the `cbor` package reaches a caller (#10).
  * `:invalid_authenticator_data` - the authenticator data is truncated
    (`AppAttest.AuthenticatorData.parse/1`).
  * `:invalid_signature` - the signature does not match the Device's
    `public_key` and `client_data`.
  * `:app_id_mismatch` - the App ID hash does not match `app_id`.
  * `:counter_not_increasing` - the Counter is not strictly greater than
    the Device's `counter`.
  """
  @type rejection ::
          :environment_mismatch
          | :invalid_assertion
          | :invalid_authenticator_data
          | :invalid_signature
          | :app_id_mismatch
          | :counter_not_increasing

  @doc """
  Validates `assertion_object` — the raw, CBOR-encoded assertion Apple's SDK
  produces — against `client_data` (the request-specific data the caller
  asked the device to sign, typically embedding a fresh server challenge),
  `app_id` (`"<Team ID>.<bundle ID>"`) and `device`, the caller's stored
  `AppAttest.Device` (what `AppAttest.Attestation.validate/6` returned, or
  the previous Assertion moved on): its `public_key`, `counter` and
  `environment`.

  Apple's own on-device API signs every Assertion over `authenticatorData`
  concatenated with the SHA-256 hash of `client_data`, never
  `authenticatorData` alone, so a genuine Assertion only verifies against
  the same `client_data` the device was asked to sign for that request.

  An Assertion carries no environment bytes of its own, so `expected_environment`
  is the environment the caller expects for this request (#170); it is
  compared against the Device's `environment`, never read off the
  assertion itself.

  Returns `{:ok, device}`, the same `AppAttest.Device` with only its
  `counter` moved on to the assertion's own Counter, for the caller to
  persist in place of the one it passed, or `{:error, rejection}`.
  """
  @spec validate(
          binary(),
          binary(),
          String.t(),
          Device.t(),
          AuthenticatorData.environment()
        ) :: {:ok, Device.t()} | {:error, rejection()}
  def validate(
        assertion_object,
        client_data,
        app_id,
        %Device{public_key: public_key, counter: stored_counter} = device,
        expected_environment
      ) do
    with :ok <- check_environment(device.environment, expected_environment),
         {:ok, %{signature: signature, auth_data: auth_data}} <-
           Envelope.decode_assertion(assertion_object),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data),
         :ok <- check_signature(auth_data, client_data, signature, public_key),
         :ok <- AuthenticatorData.check_app_id(authenticator_data, app_id),
         {:ok, counter} <- check_counter(authenticator_data, stored_counter) do
      {:ok, %Device{device | counter: counter}}
    end
  end

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
