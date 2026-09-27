defmodule AppAttest.DeviceCheckTokenTest do
  use ExUnit.Case, async: true

  alias AppAttest.{DeviceCheckToken, Fixtures}

  # 2026-01-01T00:00:00Z, pinned so the `iat` claim is asserted exactly.
  @issued_at 1_767_225_600

  describe "build/2" do
    test "carries exactly the ES256 header and the claims for its issue time" do
      device_check_key = Fixtures.device_check_key()

      [header_b64, claims_b64, _signature_b64] =
        device_check_key |> DeviceCheckToken.build(@issued_at) |> String.split(".")

      assert decode_segment(header_b64) == %{"alg" => "ES256", "kid" => "DEVCHECK01"}
      assert decode_segment(claims_b64) == %{"iss" => "TEAMID1234", "iat" => 1_767_225_600}
    end

    test "is signed by the DeviceCheck key, verifiable with its public key alone" do
      device_check_key = Fixtures.device_check_key()

      [header_b64, claims_b64, signature_b64] =
        device_check_key |> DeviceCheckToken.build(@issued_at) |> String.split(".")

      <<r::big-unsigned-integer-size(32)-unit(8), s::big-unsigned-integer-size(32)-unit(8)>> =
        Base.url_decode64!(signature_b64, padding: false)

      der_signature = :public_key.der_encode(:"Dss-Sig-Value", {:"Dss-Sig-Value", r, s})
      public_key = X509.PublicKey.derive(device_check_key.private_key)

      assert :public_key.verify(
               header_b64 <> "." <> claims_b64,
               :sha256,
               der_signature,
               public_key
             )
    end
  end

  describe "raw_signature/1" do
    # A P-256 `r` or `s` shorter than 32 bytes turns up in about 0.8 % of
    # real signatures, too rarely for a signed token to exercise it; a
    # crafted DER signature exercises the padding on every run.
    test "left-pads an r shorter than 32 bytes to a fixed-width r||s pair" do
      r = 0x01_02_03
      s = Bitwise.bsl(1, 255) + 7

      assert DeviceCheckToken.raw_signature(der_signature(r, s)) ==
               <<0::size(29)-unit(8), 1, 2, 3, s::big-unsigned-integer-size(32)-unit(8)>>
    end

    test "left-pads an s shorter than 32 bytes to a fixed-width r||s pair" do
      r = Bitwise.bsl(1, 255) + 7
      s = 0xFF

      assert DeviceCheckToken.raw_signature(der_signature(r, s)) ==
               <<r::big-unsigned-integer-size(32)-unit(8), 0::size(31)-unit(8), 0xFF>>
    end
  end

  defp der_signature(r, s), do: :public_key.der_encode(:"Dss-Sig-Value", {:"Dss-Sig-Value", r, s})

  defp decode_segment(segment),
    do: segment |> Base.url_decode64!(padding: false) |> :json.decode()
end
