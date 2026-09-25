defmodule AppAttest.RootCertificateTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Fixtures, RootCertificate}

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
               Fixtures.certificate_chain()
             )
    end

    test "is false when the real chain is checked against an unrelated root" do
      refute RootCertificate.trusted?(
               Fixtures.untrusted_root(),
               Fixtures.certificate_chain()
             )
    end

    test "is false for two certificates that were not issued from one another" do
      refute RootCertificate.trusted?(
               Fixtures.untrusted_root(),
               [Fixtures.untrusted_root()]
             )
    end

    test "is false, not a crash, for junk in place of the root or of a chain certificate" do
      [leaf_der | _intermediates] = Fixtures.certificate_chain()

      refute RootCertificate.trusted?(<<1, 2, 3>>, Fixtures.certificate_chain())
      refute RootCertificate.trusted?(RootCertificate.default(), [leaf_der, <<1, 2, 3>>])
    end

    # A real chain with any single byte of a certificate changed is proven
    # rejected, never a crash, once, through `AppAttest.Attestation.validate/6`
    # in its own test file: every certificate that still decodes goes on to
    # `trusted?/2` there.
  end
end
