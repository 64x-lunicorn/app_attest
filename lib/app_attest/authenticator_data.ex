defmodule AppAttest.AuthenticatorData do
  @moduledoc false

  # Parses the authenticator data Apple embeds in both an Attestation and an
  # Assertion, behind `AppAttest.Attestation` and `AppAttest.Assertion`; no
  # caller of the library names this module, which is why the environment
  # type lives on `AppAttest.Device`.
  #
  # Every authenticator data value starts with the same 37-byte prefix: the
  # App ID hash, a flags byte and the Counter. An Attestation's
  # authenticator data additionally carries attested credential data (an
  # aaguid and a credential ID) that identifies the newly attested key;
  # `parse/1` reads it, its fields coming back `nil` when the input is only
  # the prefix. An Assertion's authenticator data carries no attested
  # credential data, but a real device appends extension data (a CBOR map)
  # after the prefix and sets the flags' attested-credential-data bit all
  # the same (#41), so neither the length nor the flags say what follows:
  # `parse_prefix/1` reads only the prefix and ignores the rest, which the
  # Assertion's signature still covers.
  #
  # Apple's App Attest attested credential data also carries the device's
  # public key, COSE-encoded, after the credential ID. This module does not
  # decode it: `AppAttest.Attestation` reads the same public key straight
  # off the credential certificate instead (as the reference
  # implementations takimoto3/app-attest and uebelack/node-app-attest both
  # do), so nothing here needs those trailing bytes.

  alias AppAttest.Device

  defstruct [:app_id_hash, :flags, :counter, :environment, :credential_id]

  # Apple's own two fixed aaguid values (confirmed against Apple's
  # "Validating apps that connect to your server" and the reference
  # implementation takimoto3/app-attest): 16 bytes, either the
  # literal string below or "appattest" padded with seven 0x00 bytes.
  @aaguid_development "appattestdevelop"
  @aaguid_production "appattest" <> <<0, 0, 0, 0, 0, 0, 0>>

  # The App ID hash (32 bytes), the flags byte and the 4-byte Counter.
  @prefix_size 37

  # * `:app_id_hash` - SHA-256 of the app's App ID; called `rpIdHash` in
  #   Apple's own wire format, renamed here to the Spec's own term.
  # * `:flags` - the raw flags byte.
  # * `:counter` - the signature Counter.
  # * `:environment` - the environment the aaguid names; `nil` when this
  #   authenticator data carries no attested credential data, or an aaguid
  #   that is neither of Apple's two values.
  # * `:credential_id` - the attested key's ID; `nil` when this
  #   authenticator data carries no attested credential data.
  @type t :: %__MODULE__{
          app_id_hash: binary(),
          flags: byte(),
          counter: non_neg_integer(),
          environment: Device.environment() | nil,
          credential_id: binary() | nil
        }

  # Parses an Attestation's raw authenticator data into its fields, reading
  # whatever follows the prefix as attested credential data. Fails with this
  # module's own `:truncated`, which its callers translate at their seam,
  # when `data` is shorter than the fixed 37-byte prefix, or carries a
  # truncated attested credential data (a credential ID length that its own
  # remaining bytes cannot satisfy).
  @doc false
  @spec parse(binary()) :: {:ok, t()} | {:error, :truncated}
  def parse(data) do
    with {:ok, prefix} <- parse_prefix(data) do
      <<_prefix::binary-size(@prefix_size), rest::binary>> = data

      case parse_attested_credential_data(rest) do
        {:ok, aaguid, credential_id} ->
          {:ok,
           %__MODULE__{prefix | environment: environment(aaguid), credential_id: credential_id}}

        :none ->
          {:ok, prefix}

        :error ->
          {:error, :truncated}
      end
    end
  end

  # Parses only the 37-byte prefix of raw authenticator data, ignoring
  # whatever follows it: what an Assertion's authenticator data is read
  # with. The attested-credential-data fields always come back `nil`.
  # Fails with `:truncated`, like `parse/1`, when `data` is shorter than the
  # prefix.
  @doc false
  @spec parse_prefix(binary()) :: {:ok, t()} | {:error, :truncated}
  def parse_prefix(<<app_id_hash::binary-size(32), flags::8, counter::32-big, _rest::binary>>) do
    {:ok, %__MODULE__{app_id_hash: app_id_hash, flags: flags, counter: counter}}
  end

  def parse_prefix(_too_short), do: {:error, :truncated}

  # Checks `authenticator_data`'s App ID hash against `app_id`
  # (`"<Team ID>.<bundle ID>"`), the check both `AppAttest.Attestation` and
  # `AppAttest.Assertion` make identically, kept in one place so the two
  # cannot drift apart. Fails with this module's own `:other_app_id`, which
  # its callers translate at their seam.
  @doc false
  @spec check_app_id(t(), String.t()) :: :ok | {:error, :other_app_id}
  def check_app_id(%__MODULE__{app_id_hash: app_id_hash}, app_id) do
    if app_id_hash == :crypto.hash(:sha256, app_id) do
      :ok
    else
      {:error, :other_app_id}
    end
  end

  # Apple's own nonce construction, the one both an Attestation and an
  # Assertion are bound to (confirmed against "Validating apps that connect
  # to your server" and the reference implementations
  # takimoto3/app-attest and uebelack/node-app-attest, which both build and
  # verify it this same way): hash `client_data` to get clientDataHash,
  # append it to the raw authenticator data, and hash the result again.
  #
  # An Attestation's `client_data` is the one-time server challenge the
  # device attested, carried in the credential certificate's own nonce
  # extension; an Assertion's is the request-specific data the caller asked
  # the device to sign, and the nonce is what its signature covers. Built
  # here once for `AppAttest.Attestation` and `AppAttest.Assertion` alike,
  # so the two cannot build it differently.
  @doc false
  @spec nonce(binary(), binary()) :: binary()
  def nonce(auth_data, client_data) do
    :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, client_data))
  end

  defp environment(@aaguid_development), do: :development
  defp environment(@aaguid_production), do: :production
  defp environment(_neither), do: nil

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
