defmodule AppAttest.RiskMetricAppleTest do
  @moduledoc """
  `AppAttest.RiskMetric.fetch/4` against Apple's *real* development
  risk-metric endpoint, over its real `:httpc` transport — the one part of
  this module that no stand-in can prove.

  Everything `AppAttest.RiskMetricTest` asserts about the request is
  self-consistency: it checks that the JWT `fetch/4` builds verifies against
  the very key the same test generated. That cannot catch a JWT Apple
  itself rejects — a wrong signature encoding, a wrong header, a missing
  claim, a "Bearer " prefix Apple does not want. Only Apple can, and it
  says so in its own status codes ("Assessing fraud risk"): `401` for a
  token it cannot verify or that does not match the receipt, `400` for an
  incorrect environment or a bad payload.

  So the two tests below are a pair, and only the pair proves anything:

    * signed with the real DeviceCheck key, the request must *not* come back
      `401` — Apple verified the token and moved on to the receipt;
    * signed with a freshly generated key under the same DeviceCheck key
      identifier and Team ID,
      the identical request must come back `401` — Apple really checks the
      signature, rather than waving through anything shaped like a JWT.

  ## What this does not prove

  No `200`, and therefore no real receipt. The receipt sent here is the one
  embedded in the `uebelack/node-app-attest` fixture Attestation (the
  `receipt` of the `AppAttest.Device` its validation returns): a real, Apple-issued
  receipt, but issued to a foreign team and long expired, so Apple answers
  it with `400`. A `200` needs a receipt from a device running Corridor's
  own app under this Team ID, which does not exist until Corridor ships to
  TestFlight. The receipt-reading half itself is proven on real bytes
  elsewhere: `AppAttest.ReceiptTest` verifies that same Apple-issued
  `ATTEST` Receipt — its CMS envelope, its chain to Apple Root CA - G3 (and
  not to the App Attest root), Apple's own attribute list — which settles
  the root question 64x-lunicorn/Corridor#171 and 64x-lunicorn/Corridor#174
  left open. What no real bytes prove yet is a `RECEIPT`-type Receipt, the
  only type carrying a risk metric and a Not Before date: those fields are
  exercised only against the self-generated receipts in `AppAttest.Fixtures`
  (64x-lunicorn/app_attest#20).

  Tagged `:apple_endpoint`, which `test_helper.exs` excludes unless
  `AppAttest.AppleCredentials.available?/0` — a clone without an Apple
  account runs the whole suite green without them.
  """

  use ExUnit.Case, async: true

  alias AppAttest.{AppleCredentials, Attestation, Fixtures, RiskMetric, RootCertificate}

  @moduletag :apple_endpoint
  # A real round trip to Apple, over the real network.
  @moduletag timeout: 60_000

  describe "fetch/4 against Apple's real development endpoint" do
    test "Apple accepts a JWT signed by the real DeviceCheck key" do
      assert {:error, {:apple_error, status, _body}} = fetch(AppleCredentials.device_check_key!())

      refute status == 401,
             "Apple rejected the JWT AppAttest.RiskMetric built (401). " <>
               "The token, not the receipt, is what this proves: check the ES256 " <>
               "signature encoding, the header's alg and kid, and the iss/iat claims."

      # Observed, and the reason no 200 is reachable here: Apple verified the
      # token, then refused the foreign, expired receipt behind it.
      assert status == 400
    end

    test "Apple rejects a JWT signed by a forged key under the same DeviceCheck key identifier" do
      forged = %{
        AppleCredentials.device_check_key!()
        | private_key: X509.PrivateKey.new_ec(:secp256r1)
      }

      assert {:error, {:apple_error, 401, _body}} = fetch(forged)
    end
  end

  # No `opts[:transport]`: the real `:httpc` call is half of what is under
  # test here.
  defp fetch(device_check_key) do
    {:ok, device} =
      Attestation.validate(
        Fixtures.attestation(),
        Fixtures.key_id(),
        Fixtures.challenge(),
        Fixtures.app_id(),
        RootCertificate.default(),
        :development
      )

    RiskMetric.fetch(
      device,
      device_check_key,
      RootCertificate.apple_root_ca_g3()
    )
  end
end
