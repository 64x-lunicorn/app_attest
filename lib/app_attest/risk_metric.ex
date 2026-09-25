defmodule AppAttest.RiskMetric do
  @moduledoc """
  Fetches Apple's per-device App Attest risk metric, recorded alongside a
  device but never a reason to accept or reject its Attestation or
  Assertion (Corridor ADR 0007).

  Apple's own "Assessing fraud risk" guide describes this as a *receipt
  exchange*, not a per-device lookup: the caller sends whatever receipt it
  currently holds — its `AppAttest.Device`'s `receipt`, which
  `AppAttest.Attestation.validate/6` fills from the Attestation's own
  `attStmt.receipt` at first — to Apple's server, authenticated with a
  DeviceCheck JWT, and gets back a new receipt carrying the risk metric.
  No key ID appears anywhere in that request. `app_attest` holds no device
  state itself (Corridor ADR 0006): `fetch/5` returns the new receipt for
  the caller to store on its Device in place of the one it sent; it
  persists nothing on its own.

  A receipt's signature chains to Apple's general-purpose "Apple Root CA -
  G3" (`AppAttest.RootCertificate.apple_root_ca_g3/0`), not to the App
  Attest-specific root an Attestation's own chain uses
  (`AppAttest.RootCertificate.default/0`).

  Each receipt carries its own validity window, which `fetch/5` returns
  alongside the risk metric: Apple answers a refresh sent before a
  receipt's Not Before date with `304 Not Modified`, and may not honour one
  sent after its Expiration Time, so a caller schedules the next `fetch/5`
  between the two.

  The receipt is a PKCS#7/CMS SignedData structure (RFC 5652). No Hex
  package parses one, but `:public_key`'s `der_decode/2` and `der_encode/2`
  already dispatch `'ContentInfo'`, `'SignedData'`, `'SignerInfo'` and
  `'IssuerAndSerialNumber'` to a compiled-in RFC 5652 ASN.1 module, so only
  Apple's own proprietary attribute list inside the envelope — which no
  ASN.1 module describes — is parsed by hand here.
  """

  alias AppAttest.{AuthenticatorData, RootCertificate}

  @typedoc """
  The Apple DeviceCheck key that authenticates this request to Apple: an
  explicit parameter, like `AppAttest.RootCertificate`'s own root, never
  `Application` config or a compile-time flag.

    * `:key_id` - the 10-character Key ID Apple assigned this key.
    * `:team_id` - the 10-character Apple Developer Team ID (the JWT's
      `iss`; also the first segment of every App ID this key's app uses).
    * `:private_key` - the key's own EC private key material.
  """
  @type device_check_key :: %{
          key_id: String.t(),
          team_id: String.t(),
          private_key: X509.PrivateKey.t()
        }

  @typedoc """
  What the caller now persists in place of the receipt it sent.

    * `:risk_metric` - Apple's own estimate of how many distinct devices
      have used this attested key.
    * `:receipt` - the new receipt, to send on the next refresh.
    * `:not_before` - the receipt's own Not Before date. Apple answers a
      refresh sent before it with `304 Not Modified`, so a caller that wants
      a new receipt waits until this date.
    * `:expiration_time` - the receipt's own Expiration Time. Apple may
      refuse to honour a refresh sent after it, so a caller schedules one
      between the two dates.
  """
  @type result :: %{
          risk_metric: non_neg_integer(),
          receipt: binary(),
          not_before: DateTime.t(),
          expiration_time: DateTime.t()
        }

  @typedoc """
  * `:untrusted_receipt` - the receipt's signature, or its certificate
    chain against `root`, does not verify.
  * `:invalid_receipt` - Apple's response is not base64, or not a
    well-formed CMS-signed receipt carrying a risk metric.
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

  @typedoc "A request built by `fetch/5`, for `opts[:transport]` to perform."
  @type request :: %{url: charlist(), authorization: String.t(), body: binary()}

  @typedoc "What `opts[:transport]` returns: Apple's status and raw response body."
  @type transport :: (request() -> {:ok, 100..599, binary()} | {:error, term()})

  # Apple's own two risk-metric hosts and fixed path ("Assessing fraud
  # risk", confirmed directly; architecture #174's own secondary-sourced
  # guess at both hostnames turned out right).
  @production_host ~c"https://data.appattest.apple.com"
  @development_host ~c"https://data-development.appattest.apple.com"
  @path ~c"/v1/attestationData"

  # RFC 5652 pkcs7-signedData, and the one digest algorithm Apple's receipts
  # and this ticket's own JWT both use (confirmed: takimoto3/app-attest's
  # receipt fixtures, and every JWT reference architecture #174 names, are
  # SHA-256 throughout).
  @signed_data_oid {1, 2, 840, 113_549, 1, 7, 2}
  @sha256_oid {2, 16, 840, 1, 101, 3, 4, 2, 1}

  # Apple's own receipt attribute numbers ("Assessing fraud risk"): the risk
  # metric itself, and the two dates that bound when a refresh is worth
  # sending at all.
  @risk_metric_field 17
  @not_before_field 19
  @expiration_time_field 21

  # RFC 7518 section 3.4: JWS ES256 wants the signature as a fixed-width
  # r||s pair, one P-256 field element (32 bytes) each.
  @p256_coordinate_size 32

  @doc """
  Sends `receipt` (the device's current one) to Apple's risk-metric
  endpoint for `environment`, authenticated with `device_check_key`, and
  verifies the new receipt Apple returns against `root` — always
  `AppAttest.RootCertificate.apple_root_ca_g3/0` in production; a test
  substitutes its own, the same way `AppAttest.Attestation.validate/6`
  takes its own root explicitly.

  `opts[:transport]` replaces the real HTTP call to Apple with a stand-in,
  this module's only system boundary; every real caller omits it and gets
  `AppAttest.RiskMetric`'s own `:httpc`-based default.

  Returns `{:ok, result}` with the risk metric, the new receipt to persist
  in place of the one sent, and that receipt's own validity window for
  timing the next refresh, or `{:error, rejection}`. Never affects whether
  an Attestation or Assertion is accepted (Corridor ADR 0007) — nothing in
  this module is an input to either's own `validate/N`.
  """
  @spec fetch(
          binary(),
          AuthenticatorData.environment(),
          device_check_key(),
          RootCertificate.der(),
          transport: transport()
        ) :: {:ok, result()} | {:error, rejection()}
  def fetch(receipt, environment, device_check_key, root, opts \\ []) do
    transport = Keyword.get(opts, :transport, &http_request/1)

    request = %{
      url: host(environment) ++ @path,
      authorization: jwt(device_check_key),
      body: Base.encode64(receipt)
    }

    case transport.(request) do
      {:ok, 200, body} ->
        with {:ok, new_receipt} <- decode_base64(body),
             {:ok, fields} <- verify_and_extract(new_receipt, root) do
          {:ok, Map.put(fields, :receipt, new_receipt)}
        end

      {:ok, status, body} ->
        {:error, {:apple_error, status, body}}

      {:error, reason} ->
        {:error, {:transport_error, reason}}
    end
  end

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
  ## "Bearer " prefix — confirmed directly, where architecture #174's own
  ## named Go reference (an unofficial, unverified package) adds one.

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
  ## against architecture #174's own named reference implementation
  ## (takimoto3/appleapi-core's `token` package) for the header and claim
  ## shape, independent of its own "Bearer" mistake above.

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
  # conversion architecture #174's own named reference
  # (takimoto3/appleapi-core's `SignerECDSA.Sign`) performs by hand.
  defp der_signature_to_raw(der_signature) do
    {:"Dss-Sig-Value", r, s} = :public_key.der_decode(:"Dss-Sig-Value", der_signature)
    pad_to_coordinate_size(r) <> pad_to_coordinate_size(s)
  end

  defp pad_to_coordinate_size(integer) do
    bytes = :binary.encode_unsigned(integer)
    :binary.copy(<<0>>, @p256_coordinate_size - byte_size(bytes)) <> bytes
  end

  ## Receipt verification: signature and certificate chain first (a receipt
  ## nothing has verified is not trustworthy enough to read a risk metric
  ## from at all), only then the ASN.1 attribute list. Signed attributes
  ## (RFC 5652 section 5.4) are out of scope: every fixture this ticket
  ## proves against, and architecture #174's own named reference
  ## (takimoto3/app-attest), sign the content directly with none.

  defp verify_and_extract(receipt_der, root) do
    with {:ok, @signed_data_oid, signed_data} <- decode_content_info(receipt_der),
         {:SignedData, _version, _digest_algorithms, encap_content_info, certificates, _crls,
          [signer_info]} <- signed_data,
         {:EncapsulatedContentInfo, _content_type, econtent} <- encap_content_info,
         {:SignerInfo, _version, signer_id, digest_algorithm, :asn1_NOVALUE, _signature_algorithm,
          signature, _unsigned_attrs} <- signer_info,
         {:ok, :sha256} <- digest_type(digest_algorithm),
         {:ok, chain} <- signer_chain(signer_id, certificates),
         true <- RootCertificate.trusted?(root, chain),
         signer_public_key = leaf_public_key(chain),
         true <- :public_key.verify(econtent, :sha256, signature, signer_public_key),
         {:ok, attributes} <- parse_attributes(econtent) do
      extract_fields(attributes)
    else
      false -> {:error, :untrusted_receipt}
      :error -> {:error, :invalid_receipt}
      {:error, _reason} = error -> error
      _malformed -> {:error, :invalid_receipt}
    end
  end

  defp extract_fields(attributes) do
    with {:ok, risk_metric} <- field(attributes, @risk_metric_field),
         {:ok, risk_metric} <- integer_value(risk_metric),
         {:ok, not_before} <- field(attributes, @not_before_field),
         {:ok, not_before} <- timestamp_value(not_before),
         {:ok, expiration_time} <- field(attributes, @expiration_time_field),
         {:ok, expiration_time} <- timestamp_value(expiration_time) do
      {:ok, %{risk_metric: risk_metric, not_before: not_before, expiration_time: expiration_time}}
    end
  end

  defp field(attributes, number) do
    case Map.fetch(attributes, number) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, :invalid_receipt}
    end
  end

  defp integer_value(value) do
    case Integer.parse(value) do
      {integer, ""} -> {:ok, integer}
      _not_a_number -> {:error, :invalid_receipt}
    end
  end

  # Apple's own receipt date fields carry an RFC 3339 timestamp as ASCII
  # (confirmed against takimoto3/app-attest's own
  # `fraud/receipt/receipt.go`, which parses the neighbouring Creation Time
  # field the same way).
  defp timestamp_value(value) do
    case DateTime.from_iso8601(value) do
      {:ok, timestamp, _utc_offset} -> {:ok, timestamp}
      {:error, _reason} -> {:error, :invalid_receipt}
    end
  end

  defp decode_content_info(der) do
    case :public_key.der_decode(:ContentInfo, der) do
      {:ContentInfo, content_type, content} -> {:ok, content_type, content}
    end
  rescue
    _ -> {:error, :invalid_receipt}
  end

  defp digest_type({:DigestAlgorithmIdentifier, @sha256_oid, _params}), do: {:ok, :sha256}
  defp digest_type(_other), do: {:error, :invalid_receipt}

  # `certificates` (RFC 5652's `CertificateSet`) already comes back fully
  # decoded from `decode_content_info/1`, as `{:certificate, cert_record}`
  # per entry; matching `signerInfo`'s own `issuerAndSerialNumber` against
  # each is what correctly finds the signer regardless of how Apple orders
  # the set, rather than assuming it is always first.
  defp signer_chain({:issuerAndSerialNumber, {:IssuerAndSerialNumber, issuer, serial}}, certs) do
    ders =
      Enum.map(certs, fn {:certificate, cert} -> :public_key.der_encode(:Certificate, cert) end)

    case Enum.find(ders, &signed_by?(&1, issuer, serial)) do
      nil -> {:error, :untrusted_receipt}
      leaf_der -> {:ok, [leaf_der | List.delete(ders, leaf_der)]}
    end
  end

  defp signer_chain(_other_sid, _certs), do: {:error, :invalid_receipt}

  defp signed_by?(cert_der, issuer, serial) do
    certificate = X509.Certificate.from_der!(cert_der)

    X509.Certificate.issuer(certificate) == issuer and
      X509.Certificate.serial(certificate) == serial
  end

  defp leaf_public_key([leaf_der | _rest]) do
    leaf_der |> X509.Certificate.from_der!() |> X509.Certificate.public_key()
  end

  # Apple's own receipt payload (`eContent`), undocumented by any ASN.1
  # module: `SET OF SEQUENCE { type INTEGER, version INTEGER, value OCTET
  # STRING }` ("Assessing fraud risk"; confirmed structurally against
  # architecture #174's own named reference, takimoto3/app-attest's
  # `fraud/receipt/receipt.go`). Every field this ticket does not need
  # still has to be walked past correctly to reach the ones after it, so
  # this parses every attribute present, keyed by its own field number,
  # rather than searching only for field 17.
  #
  # Every parser below has a catch-all clause and returns
  # `{:error, :invalid_receipt}` rather than raising: a receipt's signature
  # and certificate chain say nothing about whether the bytes inside parse,
  # so a correctly signed receipt whose payload is truncated still has to
  # come back out of `fetch/5` as the documented rejection.

  defp parse_attributes(<<0x31, rest::binary>>) do
    with {:ok, length, rest} <- der_length(rest),
         <<attributes::binary-size(^length), _extra::binary>> <- rest do
      parse_attribute_list(attributes, %{})
    else
      _malformed -> {:error, :invalid_receipt}
    end
  end

  defp parse_attributes(_malformed), do: {:error, :invalid_receipt}

  defp parse_attribute_list(<<>>, attributes), do: {:ok, attributes}

  defp parse_attribute_list(<<0x30, rest::binary>>, attributes) do
    with {:ok, length, rest} <- der_length(rest),
         <<sequence::binary-size(^length), remaining::binary>> <- rest,
         {:ok, field, value} <- parse_attribute(sequence) do
      parse_attribute_list(remaining, Map.put(attributes, field, value))
    else
      _malformed -> {:error, :invalid_receipt}
    end
  end

  defp parse_attribute_list(_malformed, _attributes), do: {:error, :invalid_receipt}

  defp parse_attribute(<<0x02, rest::binary>>) do
    with {:ok, field, rest} <- der_integer(rest),
         <<0x02, rest::binary>> <- rest,
         {:ok, _version, rest} <- der_integer(rest),
         <<0x04, rest::binary>> <- rest,
         {:ok, length, rest} <- der_length(rest),
         <<value::binary-size(^length), _rest::binary>> <- rest do
      {:ok, field, value}
    else
      _malformed -> {:error, :invalid_receipt}
    end
  end

  defp parse_attribute(_malformed), do: {:error, :invalid_receipt}

  defp der_integer(data) do
    with {:ok, length, rest} <- der_length(data),
         <<value::big-unsigned-integer-size(^length)-unit(8), remaining::binary>> <- rest do
      {:ok, value, remaining}
    else
      _malformed -> {:error, :invalid_receipt}
    end
  end

  # DER length octets: short form (top bit clear) is the length itself;
  # long form (top bit set) gives, in its low 7 bits, how many following
  # bytes hold the length as a big-endian integer.
  defp der_length(<<0::1, short_form::7, rest::binary>>), do: {:ok, short_form, rest}

  defp der_length(<<1::1, byte_count::7, rest::binary>>) do
    case rest do
      <<length::big-unsigned-integer-size(^byte_count)-unit(8), remaining::binary>> ->
        {:ok, length, remaining}

      _malformed ->
        {:error, :invalid_receipt}
    end
  end

  defp der_length(_malformed), do: {:error, :invalid_receipt}
end
