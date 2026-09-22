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
  end
end
