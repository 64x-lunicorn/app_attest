defmodule AppAttest.DeviceCheckToken do
  @moduledoc false

  # The DeviceCheck token that authenticates `AppAttest.RiskMetric.fetch/4`
  # to Apple, built for an issue time its caller passes in, so its claims
  # and its ES256 signature encoding are tested without reading the clock.
  #
  # An APNs-style provider token: Apple's own "Assessing fraud risk" guide
  # points to the identical Apple Push Notification service token
  # procedure — ES256, header `{alg, kid}`, claims `{iss, iat}` — confirmed
  # against the reference implementation takimoto3/appleapi-core's `token`
  # package for the header and claim shape. The `kid` is the DeviceCheck
  # key identifier, not a device's Key ID.

  require Record

  Record.defrecordp(
    :ec_private_key,
    :ECPrivateKey,
    Record.extract(:ECPrivateKey, from_lib: "public_key/include/public_key.hrl")
  )

  # RFC 7518 section 3.4: JWS ES256 wants the signature as a fixed-width
  # r||s pair, one P-256 field element (32 bytes) each. ES256 is P-256 by
  # definition, and Apple issues DeviceCheck keys on no other curve, so a
  # key on any other is refused rather than signed with: its r||s would be
  # the wrong width, or `pad_to_coordinate_size/1` would raise on it.
  @p256_coordinate_size 32
  @p256_oid {1, 2, 840, 10_045, 3, 1, 7}
  @p256_curves [{:namedCurve, @p256_oid}, {:namedCurve, :secp256r1}, {:namedCurve, :prime256v1}]

  @doc false
  @spec build(AppAttest.RiskMetric.device_check_key(), integer()) ::
          {:ok, String.t()} | {:error, :not_p256_key}
  def build(%{key_id: key_id, team_id: team_id, private_key: private_key}, issued_at) do
    if p256?(private_key) do
      header = json_base64(%{"alg" => "ES256", "kid" => key_id})
      claims = json_base64(%{"iss" => team_id, "iat" => issued_at})
      signing_input = header <> "." <> claims

      signature =
        signing_input
        |> :public_key.sign(:sha256, private_key)
        |> raw_signature()
        |> Base.url_encode64(padding: false)

      {:ok, signing_input <> "." <> signature}
    else
      {:error, :not_p256_key}
    end
  end

  defp p256?(ec_private_key(parameters: parameters)), do: parameters in @p256_curves
  defp p256?(_other_key), do: false

  # :public_key.sign/3 returns a DER `Dss-Sig-Value` SEQUENCE{r, s} (the
  # same structure DSA and ECDSA signatures both use); JWS ES256 wants the
  # raw, fixed-width pair instead (RFC 7518 section 3.4) — the same
  # conversion the reference implementation takimoto3/appleapi-core's
  # `SignerECDSA.Sign` performs by hand.
  @doc false
  @spec raw_signature(binary()) :: binary()
  def raw_signature(der_signature) do
    {:"Dss-Sig-Value", r, s} = :public_key.der_decode(:"Dss-Sig-Value", der_signature)
    pad_to_coordinate_size(r) <> pad_to_coordinate_size(s)
  end

  defp pad_to_coordinate_size(integer) do
    bytes = :binary.encode_unsigned(integer)
    :binary.copy(<<0>>, @p256_coordinate_size - byte_size(bytes)) <> bytes
  end

  defp json_base64(map) do
    map |> :json.encode() |> IO.iodata_to_binary() |> Base.url_encode64(padding: false)
  end
end
