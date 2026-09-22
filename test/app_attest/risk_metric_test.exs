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
      tampered = binary_part(receipt, 0, byte_size(receipt) - 1) <> <<0>>
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
