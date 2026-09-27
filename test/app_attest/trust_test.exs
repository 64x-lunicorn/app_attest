defmodule AppAttest.TrustTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Attestation, Fixtures, Receipt, RiskMetric, Trust}

  defp common_name(der) do
    der
    |> X509.Certificate.from_der!()
    |> X509.Certificate.subject()
    |> X509.RDNSequence.get_attr(:commonName)
  end

  describe "apple/0" do
    test "holds Apple's own App Attest root for the Attestation's chain" do
      assert common_name(Trust.apple().app_attest_root) == ["Apple App Attestation Root CA"]
    end

    test "holds Apple's own general-purpose root for the Receipt's chain" do
      assert common_name(Trust.apple().receipt_root) == ["Apple Root CA - G3"]
    end
  end

  describe "each operation picks its own root" do
    test "an Attestation is checked against the App Attest root, whatever the Receipt root" do
      # A mixed Trust, the real App Attest root beside a self-generated
      # Receipt root, as the Risk metric tests use it.
      trust = %Trust{Trust.apple() | receipt_root: Fixtures.untrusted_root()}

      assert {:ok, _device} =
               Attestation.validate(
                 Fixtures.attestation(),
                 Fixtures.key_id(),
                 Fixtures.challenge(),
                 Fixtures.app_id(),
                 trust,
                 :development
               )
    end

    test "a Receipt is checked against the Receipt root, whatever the App Attest root" do
      trust = %Trust{Trust.apple() | app_attest_root: Fixtures.untrusted_root()}

      assert {:ok, %Receipt{type: :attest}} =
               Receipt.verify(Fixtures.attestation_receipt(), trust)
    end

    test "Apple's two roots swapped reject a genuine Attestation and a genuine Receipt" do
      apple = Trust.apple()
      swapped = %Trust{app_attest_root: apple.receipt_root, receipt_root: apple.app_attest_root}

      assert Attestation.validate(
               Fixtures.attestation(),
               Fixtures.key_id(),
               Fixtures.challenge(),
               Fixtures.app_id(),
               swapped,
               :development
             ) == {:error, :untrusted_root}

      assert Receipt.verify(Fixtures.attestation_receipt(), swapped) ==
               {:error, :untrusted_receipt}
    end
  end

  describe "a loose root in place of a Trust" do
    test "is refused by every operation that checks a signature chain" do
      root = Trust.apple().receipt_root
      transport = fn _request -> flunk("no request is sent without a Trust") end

      assert_raise FunctionClauseError, fn ->
        Attestation.validate(
          Fixtures.attestation(),
          Fixtures.key_id(),
          Fixtures.challenge(),
          Fixtures.app_id(),
          root,
          :development
        )
      end

      assert_raise FunctionClauseError, fn ->
        Receipt.verify(Fixtures.attestation_receipt(), root)
      end

      assert_raise FunctionClauseError, fn ->
        RiskMetric.fetch(
          %AppAttest.Device{
            public_key: "a-public-key",
            counter: 0,
            environment: :development,
            receipt: "a-receipt"
          },
          Fixtures.device_check_key(),
          root,
          transport: transport
        )
      end
    end
  end
end
