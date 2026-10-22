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

  The new receipt is verified and read by `AppAttest.Receipt.verify/3`
  against the Receipt root of the caller's `AppAttest.Trust`, Apple's
  general-purpose "Apple Root CA - G3" in `AppAttest.Trust.apple/0`, not
  the App Attest-specific root an Attestation's own chain uses: the real,
  Apple-issued Receipt inside the fixture Attestation chains to Apple Root
  CA - G3 and not to the App Attest root (`AppAttest.ReceiptTest`,
  64x-lunicorn/app_attest#23). The Trust stays an explicit parameter all
  the same. Only a Receipt of type `RECEIPT` carrying the risk metric and both
  validity dates answers this request; any other verified Receipt is
  `:invalid_receipt`.

  Each receipt carries its own validity window, which `fetch/4` returns
  alongside the risk metric: Apple answers a refresh sent before a
  receipt's Not Before date with `304 Not Modified`, and may not honour one
  sent after its Expiration Time, so a caller schedules the next `fetch/4`
  between the two.
  """

  alias AppAttest.{Device, DeviceCheckToken, Receipt, Trust}

  @typedoc """
  The Apple DeviceCheck key that authenticates this request to Apple: an
  explicit parameter, like `AppAttest.Trust`, never
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
    chain against the Receipt root of `trust`, does not verify.
  * `:certificate_expired` - the chain leads to the root, but a certificate
    of it was not valid at `opts[:at]`: already expired, or not yet valid.
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
          | :certificate_expired
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

  # How long the default transport waits to connect and for Apple's
  # answer: `:httpc`'s own default is to wait forever, which would hang
  # the calling process on a stalled connection.
  @default_timeout 10_000

  @doc """
  Sends `device`'s current `receipt` to Apple's risk-metric endpoint for
  its `environment`, authenticated with `device_check_key`, and
  verifies the new receipt Apple returns against the Receipt root of
  `trust` — `AppAttest.Trust.apple/0` in production, whose Receipt root is
  the one a real Apple Receipt chains to; a test substitutes its own, the
  same `AppAttest.Trust` that `AppAttest.Attestation.validate/6` takes.

  ## Options

  * `:transport` - replaces the real HTTP call to Apple with a stand-in,
    this module's only system boundary; every real caller omits it and gets
    `AppAttest.RiskMetric`'s own `:httpc`-based default.
  * `:at` - the time of this request, a `DateTime`; defaults to now. It
    stamps the DeviceCheck JWT's `iat` claim and is the time the new
    receipt's certificate chain must be valid at, so the request and its
    answer share one clock, and a test fixes it.
  * `:timeout` - how long the default transport waits, in milliseconds,
    to connect to Apple and for its answer; defaults to 10 000. A request
    that outlasts it is `{:transport_error, :timeout}`. Ignored with a
    `:transport` of the caller's own.

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
          Trust.t(),
          transport: transport(),
          at: DateTime.t(),
          timeout: timeout()
        ) :: {:ok, result()} | {:error, rejection()}
  def fetch(
        %Device{receipt: receipt, environment: environment} = device,
        device_check_key,
        %Trust{} = trust,
        opts \\ []
      ) do
    transport =
      Keyword.get_lazy(opts, :transport, fn ->
        &http_request(&1, timeout: Keyword.get(opts, :timeout, @default_timeout))
      end)

    at = Keyword.get_lazy(opts, :at, &DateTime.utc_now/0)

    request = %{
      url: host(environment) ++ @path,
      authorization: DeviceCheckToken.build(device_check_key, DateTime.to_unix(at)),
      body: Base.encode64(receipt)
    }

    case transport.(request) do
      {:ok, 200, body} ->
        with {:ok, new_receipt} <- decode_base64(body),
             {:ok, verified} <- verify_receipt(new_receipt, trust, at) do
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
  # does with its certificate chain's. Each keeps its meaning: the new
  # receipt does not verify, or is not a well-formed Receipt.
  defp verify_receipt(receipt, trust, at) do
    case Receipt.verify(receipt, trust, at: at) do
      {:ok, verified} -> {:ok, verified}
      {:error, :untrusted_receipt} -> {:error, :untrusted_receipt}
      {:error, :certificate_expired} -> {:error, :certificate_expired}
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
  ##
  ## Public only for its own test, which drives it against a local socket
  ## standing in for Apple's host; `fetch/4` is the seam a caller uses.

  @doc false
  @spec http_request(request(), timeout: timeout()) ::
          {:ok, 100..599, binary()} | {:error, term()}
  def http_request(%{url: url, authorization: authorization, body: body}, opts) do
    headers = [{~c"authorization", String.to_charlist(authorization)}]
    content_type = ~c"application/octet-stream"
    timeout = Keyword.fetch!(opts, :timeout)

    ssl_opts = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    # No redirect is followed: `:httpc` would repeat the POST, DeviceCheck
    # JWT and all, against whatever host a redirect named.
    http_opts = [
      ssl: ssl_opts,
      timeout: timeout,
      connect_timeout: timeout,
      autoredirect: false
    ]

    case :httpc.request(:post, {url, headers, content_type, body}, http_opts, []) do
      {:ok, {{_http_version, status, _reason}, _headers, resp_body}} ->
        {:ok, status, IO.iodata_to_binary(resp_body)}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
