defmodule AppAttest.RiskMetricTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Fixtures, RiskMetric}

  # `fetch/5`'s own transport seam (`write-tests`: mocking only at this
  # module's system boundary, Apple's HTTP endpoint) - a stand-in that
  # hands back a fixed response regardless of the request, the way a real
  # Apple server would for a given receipt.
  defp respond(status, body), do: fn _request -> {:ok, status, body} end

  describe "fetch/5" do
    test "accepts a genuine receipt and returns its risk metric" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(42, chain)
      transport = respond(200, Base.encode64(receipt))

      assert {:ok, %{risk_metric: 42, receipt: ^receipt}} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 chain.root,
                 transport: transport
               )
    end

    test "returns the receipt's own validity dates so a caller can time its refresh" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(42, chain)
      transport = respond(200, Base.encode64(receipt))

      assert {:ok, result} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 chain.root,
                 transport: transport
               )

      assert result.not_before == Fixtures.receipt_not_before()
      assert result.expiration_time == Fixtures.receipt_expiration_time()
    end

    test "sends Apple a request a real device's caller would send" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(1, chain)
      device_check_key = Fixtures.device_check_key()
      test_pid = self()

      transport = fn request ->
        send(test_pid, {:request, request})
        {:ok, 200, Base.encode64(receipt)}
      end

      assert {:ok, _result} =
               RiskMetric.fetch("previous-receipt", :production, device_check_key, chain.root,
                 transport: transport
               )

      assert_received {:request, request}
      assert request.url == ~c"https://data.appattest.apple.com/v1/attestationData"
      assert request.body == Base.encode64("previous-receipt")

      # The authorization header is a bare JWT (Apple's own "Assessing
      # fraud risk" documentation shows no "Bearer " prefix), ES256-signed
      # by the DeviceCheck key, and independently verifiable with its
      # public key alone.
      [header_b64, claims_b64, signature_b64] = String.split(request.authorization, ".")
      header = header_b64 |> Base.url_decode64!(padding: false) |> :json.decode()
      claims = claims_b64 |> Base.url_decode64!(padding: false) |> :json.decode()

      assert header == %{"alg" => "ES256", "kid" => device_check_key.key_id}
      assert claims["iss"] == device_check_key.team_id
      assert_in_delta claims["iat"], System.system_time(:second), 5

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

    test "rejects a receipt whose chain does not lead to the given root" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(1, chain)
      transport = respond(200, Base.encode64(receipt))

      assert {:error, :untrusted_receipt} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 Fixtures.untrusted_root(),
                 transport: transport
               )
    end

    test "rejects a receipt whose signed content was tampered with" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(1, chain)

      # Flipped, not overwritten with a fixed byte: the chain is generated
      # afresh every run, so a fixed byte would silently equal the original
      # about one run in 256 and leave the receipt genuine.
      flipped_last_byte = Bitwise.bxor(:binary.last(receipt), 0xFF)
      tampered = binary_part(receipt, 0, byte_size(receipt) - 1) <> <<flipped_last_byte>>
      transport = respond(200, Base.encode64(tampered))

      assert {:error, :untrusted_receipt} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 chain.root,
                 transport: transport
               )
    end

    test "rejects a response that is not a well-formed receipt" do
      transport = respond(200, Base.encode64("not a receipt"))

      assert {:error, :invalid_receipt} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end

    # A receipt Apple signed correctly, whose payload is still not something
    # this module can read: the signature and the chain say nothing about
    # whether the bytes inside parse. Each of these used to raise out of
    # `fetch/5` instead of returning the `:invalid_receipt` its own `@spec`
    # and `rejection` type promise.
    for {description, attributes} <- [
          {"whose risk metric is not a number",
           [
             {6, "RECEIPT"},
             {17, "not a number"},
             {19, "2026-01-01T00:00:00Z"},
             {21, "2026-01-08T00:00:00Z"}
           ]},
          {"whose expiration time is not a date",
           [{6, "RECEIPT"}, {17, "42"}, {19, "2026-01-01T00:00:00Z"}, {21, "whenever"}]},
          {"that carries no risk metric at all",
           [{6, "RECEIPT"}, {19, "2026-01-01T00:00:00Z"}, {21, "2026-01-08T00:00:00Z"}]},
          {"that carries no validity dates at all", [{6, "RECEIPT"}, {17, "42"}]}
        ] do
      test "rejects a receipt #{description}" do
        chain = Fixtures.risk_metric_chain()
        receipt = Fixtures.receipt_with_attributes(chain, unquote(Macro.escape(attributes)))
        transport = respond(200, Base.encode64(receipt))

        assert {:error, :invalid_receipt} =
                 RiskMetric.fetch(
                   "previous-receipt",
                   :development,
                   Fixtures.device_check_key(),
                   chain.root,
                   transport: transport
                 )
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
      test "rejects a receipt whose #{description} is truncated" do
        chain = Fixtures.risk_metric_chain()
        receipt = Fixtures.receipt_with_payload(chain, unquote(payload))
        transport = respond(200, Base.encode64(receipt))

        assert {:error, :invalid_receipt} =
                 RiskMetric.fetch(
                   "previous-receipt",
                   :development,
                   Fixtures.device_check_key(),
                   chain.root,
                   transport: transport
                 )
      end
    end

    test "rejects a response that is not base64 at all" do
      transport = respond(200, "not base64 at all!!")

      assert {:error, :invalid_receipt} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end

    test "surfaces one of Apple's own documented error responses" do
      transport = respond(401, "")

      assert {:error, {:apple_error, 401, ""}} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end

    test "surfaces a transport failure instead of raising" do
      transport = fn _request -> {:error, :timeout} end

      assert {:error, {:transport_error, :timeout}} =
               RiskMetric.fetch(
                 "previous-receipt",
                 :development,
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end
  end
end
