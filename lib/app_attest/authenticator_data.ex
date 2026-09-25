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

  @typedoc "Which App Attest environment a device was attested in (#170)."
  @type environment :: :development | :production

  # Apple's own two fixed aaguid values (architecture #174, confirmed against
  # Apple's "Validating apps that connect to your server" and the Spec's own
  # reference implementation takimoto3/app-attest): 16 bytes, either the
  # literal string below or "appattest" padded with seven 0x00 bytes.
  @aaguid_development "appattestdevelop"
  @aaguid_production "appattest" <> <<0, 0, 0, 0, 0, 0, 0>>

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

  @doc """
  Checks `authenticator_data`'s App ID hash against `app_id`
  (`"<Team ID>.<bundle ID>"`), the check both `AppAttest.Attestation` and
  `AppAttest.Assertion` make identically (duplication finding on #169).
  """
  @spec check_app_id(t(), String.t()) :: :ok | {:error, :app_id_mismatch}
  def check_app_id(authenticator_data, app_id) do
    if app_id_matches?(authenticator_data, app_id) do
      :ok
    else
      {:error, :app_id_mismatch}
    end
  end

  @doc """
  Apple's own nonce construction, the one both an Attestation and an
  Assertion are bound to (confirmed against "Validating apps that connect
  to your server" and architecture #174's reference implementations,
  takimoto3/app-attest and uebelack/node-app-attest, which both build and
  verify it this same way): hash `client_data` to get clientDataHash,
  append it to the raw authenticator data, and hash the result again.

  An Attestation's `client_data` is the one-time server challenge the
  device attested, carried in the credential certificate's own nonce
  extension; an Assertion's is the request-specific data the caller asked
  the device to sign, and the nonce is what its signature covers. Built
  here once for `AppAttest.Attestation`, `AppAttest.Assertion` and
  `AppAttest.Fixtures.assertion/4` alike (#212), the same way #169 lifted
  the identical App ID check into `check_app_id/2`.
  """
  @spec nonce(binary(), binary()) :: binary()
  def nonce(auth_data, client_data) do
    :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, client_data))
  end

  @doc """
  The App Attest environment identified by `aaguid`, as carried in an
  Attestation's `attestedCredentialData` (#170): `:development` for
  `"appattestdevelop"`, `:production` for `"appattest"` padded with seven
  0x00 bytes — Apple's own two fixed values, nothing else. Anything else,
  including `nil` (no attested credential data at all), is rejected rather
  than raising, so a malformed or forged aaguid cannot crash a caller such
  as `AppAttest.Attestation.validate/5`.
  """
  @spec environment(binary() | nil) :: environment() | {:error, :unrecognized_environment}
  def environment(@aaguid_development), do: :development
  def environment(@aaguid_production), do: :production
  def environment(_other), do: {:error, :unrecognized_environment}

  defp app_id_matches?(%__MODULE__{app_id_hash: app_id_hash}, app_id) do
    app_id_hash == :crypto.hash(:sha256, app_id)
  end

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
