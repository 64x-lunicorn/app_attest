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

  # RFC 7518 section 3.4: JWS ES256 wants the signature as a fixed-width
  # r||s pair, one P-256 field element (32 bytes) each.
  @p256_coordinate_size 32

  @doc false
  @spec build(AppAttest.RiskMetric.device_check_key(), integer()) :: String.t()
  def build(%{key_id: key_id, team_id: team_id, private_key: private_key}, issued_at) do
    header = json_base64(%{"alg" => "ES256", "kid" => key_id})
    claims = json_base64(%{"iss" => team_id, "iat" => issued_at})
    signing_input = header <> "." <> claims

    signature =
      signing_input
      |> :public_key.sign(:sha256, private_key)
      |> raw_signature()
      |> Base.url_encode64(padding: false)

    signing_input <> "." <> signature
  end

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
