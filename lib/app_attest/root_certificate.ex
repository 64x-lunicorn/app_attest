defmodule AppAttest.RootCertificate do
  @moduledoc false

  # Certificate-chain trust against one root certificate, and nothing a
  # caller calls: only `AppAttest.Attestation` and `AppAttest.Receipt` do,
  # each with the root it picks from the caller's `AppAttest.Trust`, and
  # each translates this module's own `rejection/0` into its public
  # reasons at its seam. So the chain's rejections are proven through
  # those two (`AppAttest.AttestationTest`), and the root is always the
  # explicit parameter the caller passed, never `Application` config or a
  # compile-time flag.

  require Record

  # Only for the `otp_certificate` type below: x509's own
  # `X509.Certificate.t()` names a type that does not exist, which
  # Dialyzer reports as unknown wherever a spec refers to it.
  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  @typedoc "A DER-encoded X.509 certificate."
  @type der :: binary()

  @typedoc "A decoded X.509 certificate: `:public_key`'s `:OTPCertificate` record."
  @type otp_certificate :: record(:otp_certificate)

  @typedoc """
  Every reason `trusted_leaf/3` rejects a chain. Callers translate these
  into their own reasons (`AppAttest.Attestation`, `AppAttest.Receipt`).

  * `:malformed_chain` - a certificate of `chain` is not a DER certificate
    at all.
  * `:untrusted_chain` - `chain` does not lead to `root`, including a `root`
    that is not a DER certificate at all: no chain leads to it.
  * `:expired_chain` - `chain` leads to `root`, but a certificate of it, or
    `root` itself, was not valid at the time the chain was validated at:
    not yet, or no longer.
  """
  @type rejection :: :malformed_chain | :untrusted_chain | :expired_chain

  # The trusted leaf of `chain` — a leaf-first list of DER-encoded
  # certificates, as Apple's `x5c` array carries them, not including `root`
  # itself — when it chains to the trusted `root` certificate and every
  # certificate of it was valid at `at`: `{:ok, leaf}` with the leaf
  # decoded, or `{:error, rejection}`. Every certificate is decoded once,
  # and junk in place of `root` or of any certificate in `chain` is a
  # rejection, never a raise.
  #
  # Validity is checked against `at`, never against the clock: the caller
  # passes the time it validates at, so a test validates a real, long
  # expired Apple Attestation at the time it was issued, and production
  # validates at now. A certificate that OTP's own clock finds expired is
  # re-checked against `at`, and one OTP's clock finds valid is checked
  # against `at` all the same, so `at` alone decides.
  @doc false
  @spec trusted_leaf(der(), [der(), ...], DateTime.t()) ::
          {:ok, otp_certificate()} | {:error, rejection()}
  def trusted_leaf(root, [_ | _] = chain, %DateTime{} = at) when is_binary(root) do
    # OTP's path validation raises on anything that is not a DER
    # certificate, so `root` and every certificate of `chain` are decoded
    # first, and handed on decoded, together with their own DER, so OTP
    # neither decodes them again nor re-encodes them for their signatures.
    with {:ok, [{:cert, _der, leaf} | _rest] = certificates} <- decode_chain(chain),
         {:ok, root} <- decode_root(root),
         :ok <- validate_path(root, Enum.reverse(certificates), at) do
      {:ok, leaf}
    end
  end

  # A root that is not even bytes is one no chain leads to, the same as
  # bytes that are not a certificate.
  def trusted_leaf(_root_not_bytes, [_ | _] = _chain, %DateTime{}), do: {:error, :untrusted_chain}

  defp decode_chain(chain) do
    decoded = Enum.map(chain, &decode/1)

    if Enum.all?(decoded, &match?({:ok, _certificate}, &1)),
      do: {:ok, Enum.map(decoded, fn {:ok, certificate} -> certificate end)},
      else: {:error, :malformed_chain}
  end

  defp decode_root(root) do
    case decode(root) do
      {:ok, certificate} -> {:ok, certificate}
      :error -> {:error, :untrusted_chain}
    end
  end

  # Decodes one DER-encoded certificate into OTP's own `#cert{der, otp}`
  # pair, `{:ok, cert}` or `:error`. The DER is untrusted
  # input straight from a device, and OTP's ASN.1 decoder signals damage
  # with raises, exits and throws of many kinds (`X509.Certificate.from_der/1`
  # turns only a `MatchError` into an error tuple), so every kind is caught:
  # any failure to decode is a malformed certificate, never a crash.
  #
  # OTP's decoder ignores whatever follows the certificate's own DER
  # SEQUENCE, so a certificate with bytes appended would decode, and verify,
  # the same as without them; it is rejected here instead, so one
  # certificate has one encoding.
  defp decode(der) do
    with true <- der_sequence_size(der) == byte_size(der),
         {:ok, certificate} <- X509.Certificate.from_der(der) do
      {:ok, {:cert, der, certificate}}
    else
      _not_one_certificate -> :error
    end
  catch
    _kind, _reason -> :error
  end

  # The size of the DER SEQUENCE `der` starts with, header included: its
  # length is one byte below 128, else that many following bytes (the low
  # seven bits of the first) hold it big-endian. Anything else is not a
  # DER SEQUENCE at all.
  defp der_sequence_size(<<0x30, 0::1, length::7, _rest::binary>>), do: 2 + length

  defp der_sequence_size(
         <<0x30, 1::1, count::7, length::big-unsigned-size(count)-unit(8), _::binary>>
       )
       when count > 0,
       do: 2 + count + length

  defp der_sequence_size(_not_a_der_sequence), do: :not_a_der_sequence

  # A certificate that parses can still be damaged where only path
  # validation looks (its validity times, its extensions), and OTP's
  # `pkix_path_validation/3` then raises or exits instead of returning an
  # error, for the same reason `decode/1` catches every kind.
  defp validate_path(root, path, at) do
    case :public_key.pkix_path_validation(root, path, verify_fun: {&verify_at/3, at}) do
      {:ok, _} -> :ok
      {:error, {:bad_cert, :cert_expired}} -> {:error, :expired_chain}
      {:error, _} -> {:error, :untrusted_chain}
    end
  catch
    _kind, _reason -> {:error, :untrusted_chain}
  end

  # Chain validation is otherwise OTP's own PKIX rules (RFC 5280); only the
  # validity check is made against `at` instead of OTP's clock, for the
  # reason given above `trusted_leaf/3`. OTP reports both a certificate
  # that has expired and one not yet valid as `:cert_expired`, and so does
  # this.
  defp verify_at(cert, {:bad_cert, :cert_expired}, at), do: check_validity(cert, at)
  defp verify_at(_cert, {:bad_cert, _} = reason, _at), do: {:fail, reason}
  defp verify_at(_cert, {:extension, _}, at), do: {:unknown, at}
  defp verify_at(cert, _valid_or_valid_peer, at), do: check_validity(cert, at)

  defp check_validity(cert, at) do
    {:Validity, not_before, not_after} = X509.Certificate.validity(cert)

    with {:ok, not_before} <- to_datetime(not_before),
         {:ok, not_after} <- to_datetime(not_after),
         :ok <- within(at, not_before, not_after) do
      {:valid, at}
    else
      _not_valid_at -> {:fail, :cert_expired}
    end
  end

  defp within(at, not_before, not_after) do
    if DateTime.compare(at, not_before) != :lt and DateTime.compare(at, not_after) != :gt,
      do: :ok,
      else: :not_within
  end

  # RFC 5280's two time encodings, both as OTP decodes them: UTCTime
  # (`YYMMDDHHMMSSZ`, years 1950 to 2049) and GeneralizedTime
  # (`YYYYMMDDHHMMSSZ`).
  defp to_datetime({:utcTime, [y1, y2 | _] = time}) do
    century = if [y1, y2] >= ~c"50", do: "19", else: "20"
    to_datetime({:generalTime, String.to_charlist(century) ++ time})
  end

  defp to_datetime({:generalTime, time}) do
    case to_string(time) do
      <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
        minute::binary-size(2), second::binary-size(2), "Z">> ->
        DateTime.from_iso8601("#{year}-#{month}-#{day}T#{hour}:#{minute}:#{second}Z")
        |> case do
          {:ok, datetime, 0} -> {:ok, datetime}
          _malformed -> :error
        end

      _malformed ->
        :error
    end
  end

  defp to_datetime(_other_time), do: :error
end
