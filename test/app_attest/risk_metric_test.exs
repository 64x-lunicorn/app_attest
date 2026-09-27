defmodule AppAttest.RiskMetricTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Attestation, Device, Fixtures, RiskMetric, RootCertificate}

  # `fetch/4`'s own transport seam (`write-tests`: mocking only at this
  # module's system boundary, Apple's HTTP endpoint) - a stand-in that
  # hands back a fixed response regardless of the request, the way a real
  # Apple server would for a given receipt.
  defp respond(status, body), do: fn _request -> {:ok, status, body} end

  # The Device a genuine Attestation yields: Apple's real fixture one.
  defp attested_device do
    {:ok, device} =
      Attestation.validate(
        Fixtures.attestation(),
        Fixtures.key_id(),
        Fixtures.challenge(),
        Fixtures.app_id(),
        RootCertificate.default(),
        :development
      )

    device
  end

  # A Device as a caller stored it, holding "previous-receipt" as its
  # current receipt.
  defp stored_device(environment \\ :development) do
    {_private_key, public_key} = Fixtures.device_key_pair()

    %Device{
      public_key: public_key,
      counter: 0,
      environment: environment,
      receipt: "previous-receipt"
    }
  end

  describe "fetch/4" do
    test "returns the same Device with only its Receipt replaced by Apple's new one" do
      device = attested_device()
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(42, chain)
      transport = respond(200, Base.encode64(receipt))

      assert RiskMetric.fetch(device, Fixtures.device_check_key(), chain.root,
               transport: transport
             ) ==
               {:ok,
                %{
                  device: %Device{
                    public_key: device.public_key,
                    counter: device.counter,
                    environment: device.environment,
                    receipt: receipt
                  },
                  risk_metric: 42,
                  not_before: Fixtures.receipt_not_before(),
                  expiration_time: Fixtures.receipt_expiration_time()
                }}
    end

    test "returns the receipt's own validity dates so a caller can time its refresh" do
      chain = Fixtures.risk_metric_chain()
      receipt = Fixtures.receipt(42, chain)
      transport = respond(200, Base.encode64(receipt))

      assert {:ok, result} =
               RiskMetric.fetch(
                 stored_device(),
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
               RiskMetric.fetch(stored_device(:production), device_check_key, chain.root,
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

    # A Receipt that `AppAttest.Receipt` verifies and reads, but that is not
    # what the risk-metric endpoint issues: a `RECEIPT` carrying the risk
    # metric and both validity dates.
    for {description, attributes} <- [
          {"of type ATTEST, as issued inside an Attestation",
           [{6, "ATTEST"}, {21, "2026-01-08T00:00:00Z"}]},
          {"of type ATTEST even though it carries a risk metric and both dates",
           [
             {6, "ATTEST"},
             {17, "42"},
             {19, "2026-01-01T00:00:00Z"},
             {21, "2026-01-08T00:00:00Z"}
           ]},
          {"that carries no risk metric at all",
           [{6, "RECEIPT"}, {19, "2026-01-01T00:00:00Z"}, {21, "2026-01-08T00:00:00Z"}]},
          {"that carries no Not Before date",
           [{6, "RECEIPT"}, {17, "42"}, {21, "2026-01-08T00:00:00Z"}]}
        ] do
      test "rejects a receipt #{description}" do
        chain = Fixtures.risk_metric_chain()
        receipt = Fixtures.receipt_with_attributes(chain, unquote(Macro.escape(attributes)))
        transport = respond(200, Base.encode64(receipt))

        assert {:error, :invalid_receipt} =
                 RiskMetric.fetch(
                   stored_device(),
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
                 stored_device(),
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end

    test "surfaces one of Apple's own documented error responses" do
      transport = respond(401, "")

      assert {:error, {:apple_error, 401, ""}} =
               RiskMetric.fetch(
                 stored_device(),
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end

    test "surfaces a transport failure instead of raising" do
      transport = fn _request -> {:error, :timeout} end

      assert {:error, {:transport_error, :timeout}} =
               RiskMetric.fetch(
                 stored_device(),
                 Fixtures.device_check_key(),
                 Fixtures.risk_metric_chain().root,
                 transport: transport
               )
    end
  end
end
