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

  describe "trusted_leaf/2" do
    test "yields the leaf of a real Attestation's chain against Apple's real root" do
      # This also proves an expired chain is not rejected for that alone:
      # the fixture's credCert was issued in February 2024 for a few
      # weeks' validity (App Attest leaf certificates are always
      # short-lived) and so is long expired by the time this test runs.
      # `trusted_leaf/2`'s own doc explains why that must not, on its own,
      # cause rejection.
      [leaf_der | _intermediates] = Fixtures.certificate_chain()

      assert {:ok, leaf} =
               RootCertificate.trusted_leaf(
                 RootCertificate.default(),
                 Fixtures.certificate_chain()
               )

      assert X509.Certificate.to_der(leaf) == leaf_der
    end

    test "rejects the real chain as untrusted against an unrelated root" do
      assert RootCertificate.trusted_leaf(Fixtures.untrusted_root(), Fixtures.certificate_chain()) ==
               {:error, :untrusted_chain}
    end

    test "rejects two certificates that were not issued from one another as untrusted" do
      assert RootCertificate.trusted_leaf(Fixtures.untrusted_root(), [Fixtures.untrusted_root()]) ==
               {:error, :untrusted_chain}
    end

    test "rejects junk in place of the root as untrusted, never raising" do
      assert RootCertificate.trusted_leaf(<<1, 2, 3>>, Fixtures.certificate_chain()) ==
               {:error, :untrusted_chain}
    end

    test "rejects junk in place of any certificate of the chain as malformed, never raising" do
      [leaf_der, intermediate_der] = Fixtures.certificate_chain()

      for chain <- [[<<1, 2, 3>>, intermediate_der], [leaf_der, <<1, 2, 3>>]] do
        assert RootCertificate.trusted_leaf(RootCertificate.default(), chain) ==
                 {:error, :malformed_chain}
      end
    end

    # OTP's certificate decoding and path validation raise or exit in many
    # different ways for DER that is damaged deep inside, not only for
    # junk. A fixed seed keeps the positions, and so the test, deterministic.
    test "rejects the real chain with any single byte of a certificate changed, never raising" do
      chain = Fixtures.certificate_chain()
      root = RootCertificate.default()
      state = :rand.seed_s(:exsss, {16, 16, 16})

      Enum.reduce(0..(length(chain) - 1), state, fn index, state ->
        Enum.reduce(1..200, state, fn _mutation, state ->
          der = Enum.at(chain, index)
          {position, state} = :rand.uniform_s(byte_size(der), state)
          mutated_chain = List.replace_at(chain, index, Fixtures.flip_byte(der, position - 1))

          # A changed certificate is never trusted, whether it still
          # decodes or not.
          assert RootCertificate.trusted_leaf(root, mutated_chain) in [
                   {:error, :malformed_chain},
                   {:error, :untrusted_chain}
                 ]

          state
        end)
      end)
    end
  end
end
