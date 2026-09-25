defmodule AppAttest.Receipt do
  @moduledoc """
  Verifies and reads an App Attest Receipt: Apple's signed record of a
  device's attested key.

  A Receipt comes in one of two types (Apple's field 6, "Assessing fraud
  risk"):

    * `:attest` - issued inside the Attestation (`attStmt.receipt`, the
      `receipt` of the `AppAttest.Device` that
      `AppAttest.Attestation.validate/6` returns). It carries an Expiration
      Time but no risk metric and no Not Before date.
    * `:receipt` - issued by Apple's risk-metric endpoint in exchange for the
      previous one (`AppAttest.RiskMetric.fetch/4`). Only this type carries
      the risk metric and a Not Before date.

  `AppAttest.Attestation.validate/6` hands its Receipt through unverified; a
  caller that wants that Receipt's Expiration Time calls `verify/2` on it
  with `AppAttest.RootCertificate.apple_root_ca_g3/0` itself.

  ## The trusted root

  A real Apple Receipt chains to Apple's general-purpose "Apple Root CA -
  G3" (`AppAttest.RootCertificate.apple_root_ca_g3/0`), not to the App
  Attest root an Attestation's own chain uses
  (`AppAttest.RootCertificate.default/0`): the real, Apple-issued Receipt
  inside the fixture Attestation chains Application Attestation Fraud
  Receipt Signing -> Apple Application Integration CA 5 - G1 -> Apple Root
  CA - G3, verifies against that root and does not verify against the App
  Attest root (`AppAttest.ReceiptTest`, 64x-lunicorn/app_attest#23). The
  root stays an explicit parameter all the same, so a test can substitute
  its own.

  ## Format

  The Receipt is a PKCS#7/CMS SignedData structure (RFC 5652) with one
  SignerInfo, identified by issuer and serial number, SHA-256 and no signed
  attributes, the shape of the real Apple Receipt. No Hex package parses
  one, but `:public_key`'s `der_decode/2` already dispatches
  `'ContentInfo'`, `'SignedData'`, `'SignerInfo'` and
  `'IssuerAndSerialNumber'` to a compiled-in RFC 5652 ASN.1 module, so only
  Apple's own proprietary attribute list inside the envelope, which no
  ASN.1 module describes, is parsed by hand here.
  """

  alias AppAttest.RootCertificate

  @enforce_keys [:type, :expiration_time]
  defstruct [:type, :risk_metric, :not_before, :expiration_time]

  @typedoc """
  A verified Receipt's fields.

    * `:type` - `:attest` (issued inside the Attestation) or `:receipt`
      (issued by the risk-metric endpoint).
    * `:risk_metric` - Apple's own estimate of how many distinct devices
      have used this attested key; `nil` when the Receipt carries none, as
      an `:attest` Receipt never does.
    * `:not_before` - the date before which Apple answers a refresh with
      `304 Not Modified`; `nil` when the Receipt carries none, as an
      `:attest` Receipt never does.
    * `:expiration_time` - the date after which Apple may no longer honour
      a refresh of this Receipt.
  """
  @type t :: %__MODULE__{
          type: :attest | :receipt,
          risk_metric: non_neg_integer() | nil,
          not_before: DateTime.t() | nil,
          expiration_time: DateTime.t()
        }

  @typedoc """
  * `:untrusted_receipt` - the Receipt's signature, or its certificate
    chain against the trusted root, does not verify.
  * `:invalid_receipt` - the bytes are not a well-formed CMS-signed Receipt,
    or a field it must carry is missing or unreadable.
  """
  @type rejection :: :untrusted_receipt | :invalid_receipt

  # RFC 5652 pkcs7-signedData, and the one digest algorithm Apple's Receipts
  # use (the real Apple Receipt inside the fixture Attestation, and
  # takimoto3/app-attest's receipt fixtures).
  @signed_data_oid {1, 2, 840, 113_549, 1, 7, 2}
  @sha256_oid {2, 16, 840, 1, 101, 3, 4, 2, 1}

  # Apple's own Receipt attribute numbers ("Assessing fraud risk").
  @type_field 6
  @risk_metric_field 17
  @not_before_field 19
  @expiration_time_field 21

  @doc """
  Verifies the DER-encoded `receipt` against the trusted `root` and reads
  its fields: signature and certificate chain first, since a Receipt
  nothing has verified is not trustworthy enough to read at all, only then
  Apple's attribute list.

  Returns `{:ok, receipt}` or `{:error, rejection}`; never raises, whatever
  the bytes.
  """
  @spec verify(binary(), RootCertificate.der()) :: {:ok, t()} | {:error, rejection()}
  def verify(receipt, root) when is_binary(receipt) and is_binary(root) do
    with {:ok, signed_data} <- decode_signed_data(receipt),
         {:ok, content, signature, signer_id, certificates} <- signed_content(signed_data),
         {:ok, chain} <- signer_chain(signer_id, certificates),
         :ok <- verify_chain(root, chain),
         :ok <- verify_signature(content, signature, chain),
         {:ok, attributes} <- parse_attributes(content) do
      extract_fields(attributes)
    end
  end

  def verify(_receipt, _root), do: {:error, :invalid_receipt}

  # OTP's ASN.1 decoder reports undecodable input by failing its own
  # `{:ok, _} = ...` match, so exactly that failure is caught.
  defp decode_signed_data(der) do
    case :public_key.der_decode(:ContentInfo, der) do
      {:ContentInfo, @signed_data_oid, signed_data} -> {:ok, signed_data}
      _other_content -> {:error, :invalid_receipt}
    end
  catch
    :error, {:badmatch, {:error, _reason}} -> {:error, :invalid_receipt}
  end

  defp signed_content(
         {:SignedData, _version, _digest_algorithms, {:EncapsulatedContentInfo, _type, content},
          certificates, _crls,
          [
            {:SignerInfo, _signer_version, signer_id,
             {:DigestAlgorithmIdentifier, @sha256_oid, _params}, :asn1_NOVALUE,
             _signature_algorithm, signature, _unsigned_attrs}
          ]}
       )
       when is_binary(content) and is_binary(signature) do
    {:ok, content, signature, signer_id, certificates}
  end

  defp signed_content(_malformed), do: {:error, :invalid_receipt}

  # `certificates` (RFC 5652's `CertificateSet`) comes back decoded, as
  # `{:certificate, cert_record}` per entry; matching the SignerInfo's own
  # issuer and serial number against each finds the signer regardless of
  # how Apple orders the set.
  defp signer_chain({:issuerAndSerialNumber, {:IssuerAndSerialNumber, issuer, serial}}, certs) do
    parsed =
      for {:certificate, record} <- List.wrap(certs),
          der = :public_key.der_encode(:Certificate, record),
          {:ok, certificate} <- [RootCertificate.parse(der)],
          do: {der, certificate}

    case Enum.find(parsed, fn {_der, cert} -> signed_by?(cert, issuer, serial) end) do
      nil -> {:error, :untrusted_receipt}
      {leaf_der, leaf} -> {:ok, [{leaf_der, leaf} | List.delete(parsed, {leaf_der, leaf})]}
    end
  end

  defp signer_chain(_other_signer_id, _certs), do: {:error, :invalid_receipt}

  defp signed_by?(certificate, issuer, serial) do
    X509.Certificate.issuer(certificate) == issuer and
      X509.Certificate.serial(certificate) == serial
  end

  defp verify_chain(root, chain) do
    if RootCertificate.trusted?(root, Enum.map(chain, &elem(&1, 0))),
      do: :ok,
      else: {:error, :untrusted_receipt}
  end

  defp verify_signature(content, signature, [{_leaf_der, leaf} | _rest]) do
    if :public_key.verify(content, :sha256, signature, X509.Certificate.public_key(leaf)),
      do: :ok,
      else: {:error, :untrusted_receipt}
  end

  defp extract_fields(attributes) do
    with {:ok, type} <- required(attributes, @type_field, &type_value/1),
         {:ok, risk_metric} <- optional(attributes, @risk_metric_field, &integer_value/1),
         {:ok, not_before} <- optional(attributes, @not_before_field, &timestamp_value/1),
         {:ok, expiration_time} <-
           required(attributes, @expiration_time_field, &timestamp_value/1) do
      {:ok,
       %__MODULE__{
         type: type,
         risk_metric: risk_metric,
         not_before: not_before,
         expiration_time: expiration_time
       }}
    end
  end

  defp required(attributes, number, read) do
    case Map.fetch(attributes, number) do
      {:ok, value} -> read.(value)
      :error -> {:error, :invalid_receipt}
    end
  end

  defp optional(attributes, number, read) do
    case Map.fetch(attributes, number) do
      {:ok, value} -> read.(value)
      :error -> {:ok, nil}
    end
  end

  defp type_value("ATTEST"), do: {:ok, :attest}
  defp type_value("RECEIPT"), do: {:ok, :receipt}
  defp type_value(_unknown), do: {:error, :invalid_receipt}

  defp integer_value(value) do
    case Integer.parse(value) do
      {integer, ""} -> {:ok, integer}
      _not_a_number -> {:error, :invalid_receipt}
    end
  end

  # Apple's Receipt date fields carry an RFC 3339 timestamp as ASCII, such
  # as "2024-05-04T20:27:06.193Z" in the real Apple Receipt's field 21.
  defp timestamp_value(value) do
    case DateTime.from_iso8601(value) do
      {:ok, timestamp, _utc_offset} -> {:ok, timestamp}
      {:error, _reason} -> {:error, :invalid_receipt}
    end
  end

  # Apple's own Receipt payload (`eContent`), undocumented by any ASN.1
  # module: `SET OF SEQUENCE { type INTEGER, version INTEGER, value OCTET
  # STRING }` ("Assessing fraud risk"; confirmed structurally against the
  # reference implementation takimoto3/app-attest's
  # `fraud/receipt/receipt.go` and the real Apple Receipt). Every field this
  # module does not need still has to be walked past correctly to reach the
  # ones after it, so this parses every attribute present, keyed by its own
  # field number.
  #
  # Every parser below has a catch-all clause and returns
  # `{:error, :invalid_receipt}` rather than raising: a Receipt's signature
  # and certificate chain say nothing about whether the bytes inside parse.

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
