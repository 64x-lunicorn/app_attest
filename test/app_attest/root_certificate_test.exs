defmodule AppAttest.RootCertificateTest do
  use ExUnit.Case, async: true

  alias AppAttest.RootCertificate

  describe "default/0" do
    test "is Apple's own App Attest root certificate" do
      subject =
        RootCertificate.default()
        |> X509.Certificate.from_der!()
        |> X509.Certificate.subject()
        |> X509.RDNSequence.get_attr(:commonName)

      assert subject == ["Apple App Attestation Root CA"]
    end
  end

  describe "apple_root_ca_g3/0" do
    test "is Apple's own general-purpose root, not the App Attest one" do
      subject =
        RootCertificate.apple_root_ca_g3()
        |> X509.Certificate.from_der!()
        |> X509.Certificate.subject()
        |> X509.RDNSequence.get_attr(:commonName)

      assert subject == ["Apple Root CA - G3"]
    end
  end

  describe "trusted?/2" do
    test "is true for a real Attestation's chain against Apple's real root" do
      # This also proves an expired chain is not rejected for that alone:
      # the fixture's credCert was issued in February 2024 for a few
      # weeks' validity (App Attest leaf certificates are always
      # short-lived) and so is long expired by the time this test runs.
      # `trusted?/2`'s own moduledoc explains why that must not, on its
      # own, cause rejection.
      assert RootCertificate.trusted?(
               RootCertificate.default(),
               AppAttest.Fixtures.certificate_chain()
             )
    end

    test "is false when the real chain is checked against an unrelated root" do
      refute RootCertificate.trusted?(
               AppAttest.Fixtures.untrusted_root(),
               AppAttest.Fixtures.certificate_chain()
             )
    end

    test "is false for two certificates that were not issued from one another" do
      refute RootCertificate.trusted?(
               AppAttest.Fixtures.untrusted_root(),
               [AppAttest.Fixtures.untrusted_root()]
             )
    end

    test "is false, not a crash, for junk in place of the root or of a chain certificate" do
      [leaf_der | _intermediates] = AppAttest.Fixtures.certificate_chain()

      refute RootCertificate.trusted?(<<1, 2, 3>>, AppAttest.Fixtures.certificate_chain())
      refute RootCertificate.trusted?(RootCertificate.default(), [leaf_der, <<1, 2, 3>>])
    end

    # OTP's decoder and path validation raise or exit for DER damaged deep
    # inside a certificate; a fixed seed keeps these mutations deterministic.
    test "is false, not a crash, for a real chain with any single byte of a certificate changed" do
      chain = AppAttest.Fixtures.certificate_chain()
      state = :rand.seed_s(:exsss, {16, 16, 16})

      Enum.reduce(0..(length(chain) - 1), state, fn index, state ->
        Enum.reduce(1..200, state, fn _mutation, state ->
          der = Enum.at(chain, index)
          {position, state} = :rand.uniform_s(byte_size(der), state)
          {value, state} = :rand.uniform_s(256, state)
          offset = position - 1
          <<before::binary-size(^offset), byte, rest::binary>> = der
          mutated = List.replace_at(chain, index, <<before::binary, value - 1, rest::binary>>)

          # Only a change that leaves the byte as it was can still be trusted.
          assert RootCertificate.trusted?(RootCertificate.default(), mutated) ==
                   (byte == value - 1)

          state
        end)
      end)
    end
  end
end
