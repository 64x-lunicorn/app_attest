defmodule AppAttest.RootCertificate do
  @moduledoc """
  Apple's own App Attest root certificate, and certificate-chain trust
  against it.

  The root is always an explicit parameter of every function that needs
  it, never `Application` config or a compile-time flag: `default/0`
  hands back the real Apple root as compiled-in data, but a caller (or a
  test) can substitute any other DER-encoded
  certificate to construct the chains it needs, including ones that
  must be rejected.
  """

  # Apple's own "Apple App Attestation Root CA", published at
  # https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
  # and confirmed byte-for-byte identical in two independent MIT-licensed
  # reference implementations (takimoto3/app-attest, uebelack/node-app-attest).
  @apple_app_attest_root_ca_pem """
  -----BEGIN CERTIFICATE-----
  MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
  JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
  QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
  Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
  biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
  bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
  NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
  Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
  MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
  CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
  53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
  oyFraWVIyd/dganmrduC1bmTBGwD
  -----END CERTIFICATE-----
  """

  # Apple's own general-purpose "Apple Root CA - G3", published at
  # https://www.apple.com/certificateauthority/AppleRootCA-G3.cer.
  # App Attest *receipts* (the Risk metric) are verified against this
  # root, not `default/0`'s own App Attest-specific one, on the strength of
  # takimoto3/app-attest's bundled `AppleRootCA-G3.cer` alone. Which root a
  # receipt really chains to is still open (64x-lunicorn/Corridor#171,
  # 64x-lunicorn/Corridor#174): Apple's own
  # "Assessing fraud risk" documentation names the App Attest root instead,
  # and no real Apple receipt has been verified against either root yet.
  # Corridor's first TestFlight round settles it.
  @apple_root_ca_g3_pem """
  -----BEGIN CERTIFICATE-----
  MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
  QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
  IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
  MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
  b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
  aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
  AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
  TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
  IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
  MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
  MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
  at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
  6BgD56KyKA==
  -----END CERTIFICATE-----
  """

  @typedoc "A DER-encoded X.509 certificate."
  @type der :: binary()

  @doc """
  Apple's real, compiled-in App Attest root certificate, DER-encoded.
  """
  @spec default() :: der()
  def default do
    @apple_app_attest_root_ca_pem
    |> X509.Certificate.from_pem!()
    |> X509.Certificate.to_der()
  end

  @doc """
  Apple's real, compiled-in "Apple Root CA - G3" certificate, DER-encoded:
  the root this library currently trusts for an App Attest receipt's own
  signature (`AppAttest.RiskMetric`), never for an Attestation's or
  Assertion's own chain (`default/0`). Whether a real Apple receipt chains
  to it, or to the App Attest root Apple's own documentation names, is
  still open until a real receipt has been verified
  (64x-lunicorn/Corridor#171, 64x-lunicorn/Corridor#174).
  """
  @spec apple_root_ca_g3() :: der()
  def apple_root_ca_g3 do
    @apple_root_ca_g3_pem
    |> X509.Certificate.from_pem!()
    |> X509.Certificate.to_der()
  end

  @doc """
  Whether `chain` — a leaf-first list of DER-encoded certificates, as
  Apple's `x5c` array carries them, not including `root` itself — chains
  to the trusted `root` certificate. Junk in place of `root` or of any
  certificate in `chain` is `false`, never a raise.

  Certificate validity periods are not checked. App Attest's own leaf
  certificates are short-lived by design (Apple issues a fresh one per
  Attestation, valid only a few days), and neither of this library's two
  main reference implementations (takimoto3/app-attest, in Go;
  uebelack/node-app-attest, in Node) check them either — both verify only
  the signature chain, which is what actually proves the chain leads to
  `root`.
  """
  @spec trusted?(der(), [der(), ...]) :: boolean()
  def trusted?(root, [_ | _] = chain) when is_binary(root) do
    # OTP's path validation raises on anything that is not a DER
    # certificate, so `root` and every certificate of `chain` are parsed
    # first: junk anywhere means no trusted chain, never a crash.
    Enum.all?([root | chain], &match?({:ok, _certificate}, parse(&1))) and
      path_valid?(root, Enum.reverse(chain))
  end

  @doc false
  # Parses one DER-encoded certificate, `{:ok, certificate}` or `:error`,
  # for `trusted?/2` and `AppAttest.Attestation` alike. The DER is untrusted
  # input straight from a device, and OTP's ASN.1 decoder signals damage
  # with raises, exits and throws of many kinds (`X509.Certificate.from_der/1`
  # turns only a `MatchError` into an error tuple), so every kind is caught:
  # any failure to decode is a malformed certificate, never a crash.
  @spec parse(der()) :: {:ok, X509.Certificate.t()} | :error
  def parse(der) do
    case X509.Certificate.from_der(der) do
      {:ok, certificate} -> {:ok, certificate}
      {:error, _reason} -> :error
    end
  catch
    _kind, _reason -> :error
  end

  # A certificate that parses can still be damaged where only path
  # validation looks (its validity times, its extensions), and OTP's
  # `pkix_path_validation/3` then raises or exits instead of returning an
  # error, for the same reason `parse/1` catches every kind.
  defp path_valid?(root, path) do
    case :public_key.pkix_path_validation(root, path, verify_fun: {&accept_expired/3, []}) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  catch
    _kind, _reason -> false
  end

  # Chain validation is otherwise OTP's own PKIX rules (RFC 5280); only the
  # expiry check is relaxed, for the reason `trusted?/2` documents above.
  defp accept_expired(_cert, {:bad_cert, :cert_expired}, state), do: {:valid, state}
  defp accept_expired(_cert, {:bad_cert, _} = reason, _state), do: {:fail, reason}
  defp accept_expired(_cert, {:extension, _}, state), do: {:unknown, state}
  defp accept_expired(_cert, _valid_or_valid_peer, state), do: {:valid, state}
end
