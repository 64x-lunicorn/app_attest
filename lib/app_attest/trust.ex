defmodule AppAttest.Trust do
  @moduledoc """
  The roots a caller trusts, one per signature chain App Attest checks,
  passed as one value to every operation that checks such a chain.

  Apple signs App Attest's two chains under two different roots:

    * `:app_attest_root` - the root an Attestation's own certificate chain
      leads to, Apple's "Apple App Attestation Root CA".
    * `:receipt_root` - the root a Receipt's certificate chain leads to,
      Apple's general-purpose "Apple Root CA - G3".

  `AppAttest.Attestation.validate/6` checks against the first,
  `AppAttest.Receipt.verify/2` and `AppAttest.RiskMetric.fetch/4` against
  the second; each picks its own, so a caller never pairs a root with an
  operation by hand. A wrong pairing would be rejected exactly like a
  forgery: the real Attestation does not chain to Apple Root CA - G3, and
  the real Receipt inside it does not chain to the App Attest root
  (`AppAttest.TrustTest`).

  A `Trust` is always an explicit parameter, never `Application` config or
  a compile-time flag: `apple/0` hands back Apple's real pair as
  compiled-in data, and a test builds its own, from self-generated roots
  or from one of Apple's beside a self-generated one:

      %AppAttest.Trust{AppAttest.Trust.apple() | receipt_root: test_root}
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
  # App Attest Receipts are verified against this root, not against the
  # App Attest-specific one above. Verified on the real, Apple-issued Receipt
  # inside the fixture Attestation (64x-lunicorn/app_attest#23,
  # `AppAttest.ReceiptTest`): its chain runs Application Attestation Fraud
  # Receipt Signing -> Apple Application Integration CA 5 - G1 -> Apple Root
  # CA - G3, and it verifies against this root and not against the App Attest root.
  # This settles the root question 64x-lunicorn/Corridor#171 and
  # 64x-lunicorn/Corridor#174 left open.
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

  @enforce_keys [:app_attest_root, :receipt_root]
  defstruct [:app_attest_root, :receipt_root]

  @typedoc """
  The two roots, each a DER-encoded certificate.

    * `:app_attest_root` - the root an Attestation's chain must lead to.
    * `:receipt_root` - the root a Receipt's chain must lead to.
  """
  @type t :: %__MODULE__{
          app_attest_root: binary(),
          receipt_root: binary()
        }

  @doc """
  Apple's real, compiled-in pair: "Apple App Attestation Root CA" for an
  Attestation's chain and "Apple Root CA - G3" for a Receipt's.
  """
  @spec apple() :: t()
  def apple do
    %__MODULE__{
      app_attest_root: to_der(@apple_app_attest_root_ca_pem),
      receipt_root: to_der(@apple_root_ca_g3_pem)
    }
  end

  defp to_der(pem), do: pem |> X509.Certificate.from_pem!() |> X509.Certificate.to_der()
end
