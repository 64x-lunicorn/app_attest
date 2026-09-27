defmodule AppAttest.ReceiptTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Fixtures, Receipt, Trust}

  describe "verify/2 with the real Apple Receipt inside the fixture Attestation" do
    test "verifies against Apple Root CA - G3 and reads as an ATTEST Receipt without a risk metric" do
      # Field 21 of that Receipt, read once from its bytes: "2024-05-04T20:27:06.193Z".
      assert {:ok,
              %Receipt{
                type: :attest,
                risk_metric: nil,
                not_before: nil,
                expiration_time: ~U[2024-05-04 20:27:06.193Z]
              }} =
               Receipt.verify(Fixtures.attestation_receipt(), Trust.apple())
    end

    test "does not verify against the App Attest root an Attestation's own chain uses" do
      assert {:error, :untrusted_receipt} =
               Receipt.verify(
                 Fixtures.attestation_receipt(),
                 %Trust{Trust.apple() | receipt_root: Trust.apple().app_attest_root}
               )
    end

    # Every prefix of a real Receipt: undecodable at every length, never a raise.
    test "rejects every truncation of it as invalid, never raising" do
      receipt = Fixtures.attestation_receipt()

      for length <- 0..(byte_size(receipt) - 1) do
        assert {:error, :invalid_receipt} =
                 Receipt.verify(
                   binary_part(receipt, 0, length),
                   Trust.apple()
                 )
      end
    end

    # One byte flipped at every position, wherever in the envelope, the
    # certificates or the content it lands: never a raise. Some flips land
    # in fields no signature covers (an algorithm identifier outside the
    # signed data, a version number) and still verify, so the outcome is any
    # of the documented ones.
    test "answers it with any single byte flipped, never raising" do
      receipt = Fixtures.attestation_receipt()
      trust = Trust.apple()
      genuine = Receipt.verify(receipt, trust)

      for position <- 0..(byte_size(receipt) - 1) do
        assert Receipt.verify(Fixtures.flip_byte(receipt, position), trust) in [
                 {:error, :untrusted_receipt},
                 {:error, :invalid_receipt},
                 genuine
               ]
      end
    end
  end

  describe "verify/2 with a self-generated Receipt" do
    test "reads a genuine RECEIPT's type, risk metric and validity dates" do
      chain = Fixtures.risk_metric_chain()

      assert {:ok,
              %Receipt{
                type: :receipt,
                risk_metric: 42,
                not_before: ~U[2026-01-01 00:00:00Z],
                expiration_time: ~U[2026-01-08 00:00:00Z]
              }} = Receipt.verify(Fixtures.receipt(42, chain), chain.trust)
    end

    test "rejects a Receipt whose chain does not lead to the given root" do
      chain = Fixtures.risk_metric_chain()

      assert {:error, :untrusted_receipt} =
               Receipt.verify(
                 Fixtures.receipt(1, chain),
                 %Trust{Trust.apple() | receipt_root: Fixtures.untrusted_root()}
               )
    end

    test "rejects a Receipt whose signed content was tampered with" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(1, chain)

      # Flipped, not overwritten with a fixed byte: the chain is generated
      # afresh every run, so a fixed byte would silently equal the original
      # about one run in 256 and leave the Receipt genuine.
      tampered = Fixtures.flip_byte(receipt, byte_size(receipt) - 1)

      assert {:error, :untrusted_receipt} = Receipt.verify(tampered, chain.trust)
    end

    test "rejects bytes that are not a Receipt at all" do
      assert {:error, :invalid_receipt} =
               Receipt.verify("not a receipt", Fixtures.risk_metric_chain().trust)
    end

    test "rejects something that is not bytes at all, never raising" do
      assert {:error, :invalid_receipt} =
               Receipt.verify(nil, Fixtures.risk_metric_chain().trust)
    end

    # A Receipt signed correctly whose fields are still not something this
    # module can read: the signature and the chain say nothing about
    # whether the bytes inside parse.
    for {description, attributes} <- [
          {"whose risk metric is not a number",
           [
             {6, "RECEIPT"},
             {17, "not a number"},
             {19, "2026-01-01T00:00:00Z"},
             {21, "2026-01-08T00:00:00Z"}
           ]},
          {"whose Not Before is not a date",
           [{6, "RECEIPT"}, {17, "42"}, {19, "soon"}, {21, "2026-01-08T00:00:00Z"}]},
          {"whose expiration time is not a date",
           [{6, "RECEIPT"}, {17, "42"}, {19, "2026-01-01T00:00:00Z"}, {21, "whenever"}]},
          {"that carries no expiration time", [{6, "ATTEST"}]},
          {"that carries no validity dates at all", [{6, "RECEIPT"}, {17, "42"}]},
          {"that carries no type", [{21, "2026-01-08T00:00:00Z"}]},
          {"whose type is neither ATTEST nor RECEIPT",
           [{6, "SOMETHING"}, {21, "2026-01-08T00:00:00Z"}]}
        ] do
      test "rejects a Receipt #{description}" do
        chain = Fixtures.risk_metric_chain()
        receipt = Fixtures.receipt_with_attributes(chain, unquote(Macro.escape(attributes)))

        assert {:error, :invalid_receipt} = Receipt.verify(receipt, chain.trust)
      end
    end

    # Truncated lengths at each level of Apple's own attribute list: the
    # outer SET, one attribute SEQUENCE, an attribute's own INTEGER, and its
    # value's OCTET STRING.
    for {description, payload} <- [
          {"outer attribute set", <<0x31, 0x7F, 0x30>>},
          {"attribute sequence", <<0x31, 0x02, 0x30, 0x7F>>},
          {"attribute's field number", <<0x31, 0x04, 0x30, 0x02, 0x02, 0x7F>>},
          {"attribute's value", <<0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x11, 0x02, 0x01, 0x01>>}
        ] do
      test "rejects a Receipt whose #{description} is truncated" do
        chain = Fixtures.risk_metric_chain()
        receipt = Fixtures.receipt_with_payload(chain, unquote(payload))

        assert {:error, :invalid_receipt} = Receipt.verify(receipt, chain.trust)
      end
    end
  end
end
