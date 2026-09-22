defmodule AppAttest.RootCertificate do
  @moduledoc """
  Apple's own App Attest root certificate, and certificate-chain trust
  against it.

  The root is always an explicit parameter of every function that needs
  it, never `Application` config or a compile-time flag: `default/0`
  hands back the real Apple root as compiled-in data, but a caller (or a
  test, per architecture #174) can substitute any other DER-encoded
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
  Whether `chain` — a leaf-first list of DER-encoded certificates, as
  Apple's `x5c` array carries them, not including `root` itself — chains
  to the trusted `root` certificate.

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
    path = Enum.reverse(chain)

    case :public_key.pkix_path_validation(root, path, verify_fun: {&accept_expired/3, []}) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  # Chain validation is otherwise OTP's own PKIX rules (RFC 5280); only the
  # expiry check is relaxed, for the reason `trusted?/2` documents above.
  defp accept_expired(_cert, {:bad_cert, :cert_expired}, state), do: {:valid, state}
  defp accept_expired(_cert, {:bad_cert, _} = reason, _state), do: {:fail, reason}
  defp accept_expired(_cert, {:extension, _}, state), do: {:unknown, state}
  defp accept_expired(_cert, _valid_or_valid_peer, state), do: {:valid, state}
end
