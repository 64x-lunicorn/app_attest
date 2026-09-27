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
  Every reason `trusted_leaf/2` rejects a chain. Callers translate these
  into their own reasons (`AppAttest.Attestation`, `AppAttest.Receipt`).

  * `:malformed_chain` - a certificate of `chain` is not a DER certificate
    at all.
  * `:untrusted_chain` - `chain` does not lead to `root`, including a `root`
    that is not a DER certificate at all: no chain leads to it.
  """
  @type rejection :: :malformed_chain | :untrusted_chain

  # The trusted leaf of `chain` — a leaf-first list of DER-encoded
  # certificates, as Apple's `x5c` array carries them, not including `root`
  # itself — when it chains to the trusted `root` certificate: `{:ok, leaf}`
  # with the leaf decoded, or `{:error, rejection}`. Every certificate is
  # decoded once, and junk in place of `root` or of any certificate in
  # `chain` is a rejection, never a raise.
  #
  # Certificate validity periods are not checked. App Attest's own leaf
  # certificates are short-lived by design (Apple issues a fresh one per
  # Attestation, valid only a few days), and neither of this library's two
  # main reference implementations (takimoto3/app-attest, in Go;
  # uebelack/node-app-attest, in Node) check them either — both verify only
  # the signature chain, which is what actually proves the chain leads to
  # `root`.
  @doc false
  @spec trusted_leaf(der(), [der(), ...]) :: {:ok, otp_certificate()} | {:error, rejection()}
  def trusted_leaf(root, [_ | _] = chain) when is_binary(root) do
    # OTP's path validation raises on anything that is not a DER
    # certificate, so `root` and every certificate of `chain` are decoded
    # first, and handed on decoded, together with their own DER, so OTP
    # neither decodes them again nor re-encodes them for their signatures.
    with {:ok, [{:cert, _der, leaf} | _rest] = certificates} <- decode_chain(chain),
         {:ok, root} <- decode_root(root),
         :ok <- validate_path(root, Enum.reverse(certificates)) do
      {:ok, leaf}
    end
  end

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
  defp decode(der) do
    case X509.Certificate.from_der(der) do
      {:ok, certificate} -> {:ok, {:cert, der, certificate}}
      {:error, _reason} -> :error
    end
  catch
    _kind, _reason -> :error
  end

  # A certificate that parses can still be damaged where only path
  # validation looks (its validity times, its extensions), and OTP's
  # `pkix_path_validation/3` then raises or exits instead of returning an
  # error, for the same reason `decode/1` catches every kind.
  defp validate_path(root, path) do
    case :public_key.pkix_path_validation(root, path, verify_fun: {&accept_expired/3, []}) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :untrusted_chain}
    end
  catch
    _kind, _reason -> {:error, :untrusted_chain}
  end

  # Chain validation is otherwise OTP's own PKIX rules (RFC 5280); only the
  # expiry check is relaxed, for the reason given above `trusted_leaf/2`.
  defp accept_expired(_cert, {:bad_cert, :cert_expired}, state), do: {:valid, state}
  defp accept_expired(_cert, {:bad_cert, _} = reason, _state), do: {:fail, reason}
  defp accept_expired(_cert, {:extension, _}, state), do: {:unknown, state}
  defp accept_expired(_cert, _valid_or_valid_peer, state), do: {:valid, state}
end
