defmodule AppAttest.RiskMetric do
  @moduledoc """
  Fetches Apple's per-device App Attest risk metric, recorded alongside a
  device but never a reason to accept or reject its Attestation or
  Assertion (Corridor ADR 0007).

  Apple's own "Assessing fraud risk" guide describes this as a *receipt
  exchange*, not a per-device lookup: the Device's current receipt — which
  `AppAttest.Attestation.validate/6` fills from the Attestation's own
  `attStmt.receipt` at first — goes to Apple's server, authenticated with a
  DeviceCheck JWT, and a new receipt carrying the risk metric comes back.
  The device's Key ID appears nowhere in that request. `app_attest` holds
  no device state itself (Corridor ADR 0006): `fetch/4` takes the caller's
  stored `AppAttest.Device` and returns it with its Receipt moved on, for
  the caller to persist in place of the one it passed; it persists nothing
  on its own.

  The new receipt is verified and read by `AppAttest.Receipt.verify/2`
  against Apple's general-purpose "Apple Root CA - G3"
  (`AppAttest.RootCertificate.apple_root_ca_g3/0`), not the App
  Attest-specific root an Attestation's own chain uses
  (`AppAttest.RootCertificate.default/0`): the real, Apple-issued Receipt
  inside the fixture Attestation chains to Apple Root CA - G3 and not to
  the App Attest root (`AppAttest.ReceiptTest`,
  64x-lunicorn/app_attest#23). `root` stays an explicit parameter all the
  same. Only a Receipt of type `RECEIPT` carrying the risk metric and both
  validity dates answers this request; any other verified Receipt is
  `:invalid_receipt`.

  Each receipt carries its own validity window, which `fetch/4` returns
  alongside the risk metric: Apple answers a refresh sent before a
  receipt's Not Before date with `304 Not Modified`, and may not honour one
  sent after its Expiration Time, so a caller schedules the next `fetch/4`
  between the two.
  """

  alias AppAttest.{Device, Receipt, RootCertificate}

  @typedoc """
  The Apple DeviceCheck key that authenticates this request to Apple: an
  explicit parameter, like `AppAttest.RootCertificate`'s own root, never
  `Application` config or a compile-time flag.

    * `:key_id` - the 10-character DeviceCheck key identifier Apple
      assigned this key (the JWT's `kid`); not a device's Key ID.
    * `:team_id` - the 10-character Apple Developer Team ID (the JWT's
      `iss`; also the first segment of every App ID this key's app uses).
    * `:private_key` - the key's own EC private key material.
  """
  @type device_check_key :: %{
          key_id: String.t(),
          team_id: String.t(),
          private_key: :public_key.ecdsa_private_key()
        }

  @typedoc """
  What a successful `fetch/4` returns.

    * `:device` - the Device passed in, with only its `receipt` replaced by
      Apple's new one, for the caller to persist in its place; the next
      refresh sends that receipt.
    * `:risk_metric` - Apple's own estimate of how many distinct devices
      have used this attested key.
    * `:not_before` - the receipt's own Not Before date. Apple answers a
      refresh sent before it with `304 Not Modified`, so a caller that wants
      a new receipt waits until this date.
    * `:expiration_time` - the receipt's own Expiration Time. Apple may
      refuse to honour a refresh sent after it, so a caller schedules one
      between the two dates.
  """
  @type result :: %{
          device: Device.t(),
          risk_metric: non_neg_integer(),
          not_before: DateTime.t(),
          expiration_time: DateTime.t()
        }

  @typedoc """
  * `:untrusted_receipt` - the receipt's signature, or its certificate
    chain against `root`, does not verify.
  * `:invalid_receipt` - Apple's response is not base64, or not a
    well-formed CMS-signed receipt of type `RECEIPT` carrying a risk metric
    and both validity dates.
  * `{:apple_error, status, body}` - Apple's server answered with a status
    other than 200 (its own documented codes: 304, 400, 401, 404, 429, 500,
    503 — see "Assessing fraud risk").
  * `{:transport_error, reason}` - the request to Apple itself failed.
  """
  @type rejection ::
          :untrusted_receipt
          | :invalid_receipt
          | {:apple_error, non_neg_integer(), binary()}
          | {:transport_error, term()}

  @typedoc "A request built by `fetch/4`, for `opts[:transport]` to perform."
  @type request :: %{url: charlist(), authorization: String.t(), body: binary()}

  @typedoc "What `opts[:transport]` returns: Apple's status and raw response body."
  @type transport :: (request() -> {:ok, 100..599, binary()} | {:error, term()})

  # Apple's own two risk-metric hosts and fixed path ("Assessing fraud
  # risk").
  @production_host ~c"https://data.appattest.apple.com"
  @development_host ~c"https://data-development.appattest.apple.com"
  @path ~c"/v1/attestationData"

  # RFC 7518 section 3.4: JWS ES256 wants the signature as a fixed-width
  # r||s pair, one P-256 field element (32 bytes) each.
  @p256_coordinate_size 32

  @doc """
  Sends `device`'s current `receipt` to Apple's risk-metric endpoint for
  its `environment`, authenticated with `device_check_key`, and
  verifies the new receipt Apple returns against `root` —
  `AppAttest.RootCertificate.apple_root_ca_g3/0` in production, the root a
  real Apple Receipt chains to; a test substitutes its own, the same way `AppAttest.Attestation.validate/6`
  takes its own root explicitly.

  `opts[:transport]` replaces the real HTTP call to Apple with a stand-in,
  this module's only system boundary; every real caller omits it and gets
  `AppAttest.RiskMetric`'s own `:httpc`-based default.

  Returns `{:ok, result}` with the Device carrying the new receipt, to
  persist in place of the one passed, the risk metric, and that receipt's
  own validity window for timing the next refresh, or `{:error, rejection}`;
  on an error the caller keeps the Device it has. Never affects whether
  an Attestation or Assertion is accepted (Corridor ADR 0007) — nothing in
  this module is an input to either's own `validate/N`.
  """
  @spec fetch(
          Device.t(),
          device_check_key(),
          RootCertificate.der(),
          transport: transport()
        ) :: {:ok, result()} | {:error, rejection()}
  def fetch(
        %Device{receipt: receipt, environment: environment} = device,
        device_check_key,
        root,
        opts \\ []
      ) do
    transport = Keyword.get(opts, :transport, &http_request/1)

    request = %{
      url: host(environment) ++ @path,
      authorization: jwt(device_check_key),
      body: Base.encode64(receipt)
    }

    case transport.(request) do
      {:ok, 200, body} ->
        with {:ok, new_receipt} <- decode_base64(body),
             {:ok, verified} <- verify_receipt(new_receipt, root) do
          risk_metric_fields(verified, %Device{device | receipt: new_receipt})
        end

      {:ok, status, body} ->
        {:error, {:apple_error, status, body}}

      {:error, reason} ->
        {:error, {:transport_error, reason}}
    end
  end

  # Receipt's own reasons are translated here, at this seam, so every atom
  # of `rejection/0` is minted in this module, as `AppAttest.Attestation`
  # does with `AppAttest.RootCertificate`'s. Each keeps its meaning: the
  # new receipt does not verify, or is not a well-formed Receipt.
  defp verify_receipt(receipt, root) do
    case Receipt.verify(receipt, root) do
      {:ok, verified} -> {:ok, verified}
      {:error, :untrusted_receipt} -> {:error, :untrusted_receipt}
      {:error, :invalid_receipt} -> {:error, :invalid_receipt}
    end
  end

  # Only a `RECEIPT` (the type the risk-metric endpoint issues) carrying the
  # risk metric and its Not Before date is an answer to this request; an
  # `ATTEST` Receipt or one missing either field is not.
  defp risk_metric_fields(
         %Receipt{type: :receipt, risk_metric: risk_metric, not_before: not_before} = verified,
         device
       )
       when is_integer(risk_metric) and not is_nil(not_before) do
    {:ok,
     %{
       device: device,
       risk_metric: risk_metric,
       not_before: not_before,
       expiration_time: verified.expiration_time
     }}
  end

  defp risk_metric_fields(_other_receipt, _device), do: {:error, :invalid_receipt}

  defp host(:development), do: @development_host
  defp host(:production), do: @production_host

  defp decode_base64(body) do
    case Base.decode64(String.trim(body)) do
      {:ok, receipt} -> {:ok, receipt}
      :error -> {:error, :invalid_receipt}
    end
  end

  ## HTTP transport: the real default, `:httpc` (part of Erlang/OTP's own
  ## `:inets`, no new Hex dependency) against Apple's real host. Apple's own
  ## "Assessing fraud risk" curl example sends the header bare, with no
  ## "Bearer " prefix, although some unofficial client libraries add one.

  defp http_request(%{url: url, authorization: authorization, body: body}) do
    headers = [{~c"authorization", String.to_charlist(authorization)}]
    content_type = ~c"application/octet-stream"

    ssl_opts = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    case :httpc.request(:post, {url, headers, content_type, body}, [ssl: ssl_opts], []) do
      {:ok, {{_http_version, status, _reason}, _headers, resp_body}} ->
        {:ok, status, IO.iodata_to_binary(resp_body)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## JWT (APNs-style provider token): Apple's own "Assessing fraud risk"
  ## guide points to the identical Apple Push Notification service token
  ## procedure — ES256, header `{alg, kid}`, claims `{iss, iat}` — confirmed
  ## against the reference implementation takimoto3/appleapi-core's `token`
  ## package for the header and claim shape. The `kid` is the DeviceCheck
  ## key identifier, not a device's Key ID.

  defp jwt(%{key_id: key_id, team_id: team_id, private_key: private_key}) do
    header = json_base64(%{"alg" => "ES256", "kid" => key_id})
    claims = json_base64(%{"iss" => team_id, "iat" => System.system_time(:second)})
    signing_input = header <> "." <> claims

    signature =
      signing_input
      |> :public_key.sign(:sha256, private_key)
      |> der_signature_to_raw()
      |> Base.url_encode64(padding: false)

    signing_input <> "." <> signature
  end

  defp json_base64(map) do
    map |> :json.encode() |> IO.iodata_to_binary() |> Base.url_encode64(padding: false)
  end

  # :public_key.sign/3 returns a DER `Dss-Sig-Value` SEQUENCE{r, s} (the
  # same structure DSA and ECDSA signatures both use); JWS ES256 wants the
  # raw, fixed-width pair instead (RFC 7518 section 3.4) — the same
  # conversion the reference implementation takimoto3/appleapi-core's
  # `SignerECDSA.Sign` performs by hand.
  defp der_signature_to_raw(der_signature) do
    {:"Dss-Sig-Value", r, s} = :public_key.der_decode(:"Dss-Sig-Value", der_signature)
    pad_to_coordinate_size(r) <> pad_to_coordinate_size(s)
  end

  defp pad_to_coordinate_size(integer) do
    bytes = :binary.encode_unsigned(integer)
    :binary.copy(<<0>>, @p256_coordinate_size - byte_size(bytes)) <> bytes
  end
end
