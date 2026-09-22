defmodule AppAttest.AuthenticatorData do
  @moduledoc """
  Parses the authenticator data Apple embeds in both an Attestation and an
  Assertion (architecture #174).

  Every authenticator data value starts with the same 37-byte prefix: the
  App ID hash, a flags byte and the Counter. An Attestation's authenticator
  data is the structural superset — it additionally carries attested
  credential data (an aaguid and a credential ID) that identifies the newly
  attested key. `parse/1` handles both shapes: the attested-credential-data
  fields come back `nil` when the input is only the 37-byte prefix, the
  shape #169's Assertion validation reuses.

  Apple's App Attest attested credential data also carries the device's
  public key, COSE-encoded, after the credential ID. This module does not
  decode it: `AppAttest.Attestation` reads the same public key straight off
  the credential certificate instead (architecture #174's own reference
  implementations, takimoto3/app-attest and uebelack/node-app-attest, both
  do this), so nothing here needs those trailing bytes.
  """

  defstruct [:app_id_hash, :flags, :counter, :aaguid, :credential_id]

  @typedoc """
  * `:app_id_hash` - SHA-256 of the app's App ID; called `rpIdHash` in
    Apple's own wire format, renamed here to the Spec's own term.
  * `:flags` - the raw flags byte.
  * `:counter` - the signature Counter.
  * `:aaguid` - 16 bytes identifying development vs production (#170); `nil`
    when this authenticator data carries no attested credential data.
  * `:credential_id` - the attested key's ID; `nil` for the same reason.
  """
  @type t :: %__MODULE__{
          app_id_hash: binary(),
          flags: byte(),
          counter: non_neg_integer(),
          aaguid: binary() | nil,
          credential_id: binary() | nil
        }

  @doc """
  Parses raw authenticator data into its fields.

  Fails with `:invalid_authenticator_data` when `data` is shorter than the
  fixed 37-byte prefix, or carries a truncated attested credential data
  (a credential ID length that its own remaining bytes cannot satisfy).
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, :invalid_authenticator_data}
  def parse(<<app_id_hash::binary-size(32), flags::8, counter::32-big, rest::binary>>) do
    case parse_attested_credential_data(rest) do
      {:ok, aaguid, credential_id} ->
        {:ok,
         %__MODULE__{
           app_id_hash: app_id_hash,
           flags: flags,
           counter: counter,
           aaguid: aaguid,
           credential_id: credential_id
         }}

      :none ->
        {:ok, %__MODULE__{app_id_hash: app_id_hash, flags: flags, counter: counter}}

      :error ->
        {:error, :invalid_authenticator_data}
    end
  end

  def parse(_too_short), do: {:error, :invalid_authenticator_data}

  @doc "Whether `authenticator_data`'s App ID hash matches `app_id` (`\"<Team ID>.<bundle ID>\"`)."
  @spec app_id_matches?(t(), String.t()) :: boolean()
  def app_id_matches?(%__MODULE__{app_id_hash: app_id_hash}, app_id) do
    app_id_hash == :crypto.hash(:sha256, app_id)
  end

  @doc false
  # Shared with `AppAttest.Attestation` and `AppAttest.Assertion`: the `cbor`
  # package wraps every decoded CBOR byte string (the format Apple uses for
  # authData, each x5c certificate, an Assertion's own signature and
  # authenticatorData) in a `%CBOR.Tag{tag: :bytes, value: binary}`, rather
  # than handing back the raw binary directly (its own README explains why).
  @spec unwrap_bytes(CBOR.Tag.t()) :: binary()
  def unwrap_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value

  defp parse_attested_credential_data(<<>>), do: :none

  defp parse_attested_credential_data(
         <<aaguid::binary-size(16), credential_id_length::16-big, rest::binary>>
       )
       when byte_size(rest) >= credential_id_length do
    <<credential_id::binary-size(^credential_id_length), _cose_public_key::binary>> = rest
    {:ok, aaguid, credential_id}
  end

  defp parse_attested_credential_data(_truncated), do: :error
end
