defmodule AppAttest.AttestationTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Attestation, Fixtures, RootCertificate}

  # The four scenarios Spec #166 and ticket #168 name verbatim run as
  # black-box tests against this module's public API, in
  # test/integration/app_attest_integration_test.exs. This file covers one
  # more rejection that Apple's own attested credential data makes
  # possible, and that ticket #168's own seam (`key_id`, architecture #174)
  # would otherwise leave unused: the attested credential ID not matching
  # the key identifier the caller expected.
  describe "validate/5" do
    test "is rejected when the attested credential ID does not match key_id" do
      assert Attestation.validate(
               Fixtures.attestation(),
               "a-different-key-id",
               Fixtures.challenge(),
               Fixtures.app_id(),
               RootCertificate.default()
             ) == {:error, :key_id_mismatch}
    end
  end
end
