defmodule AppAttest.Device do
  @moduledoc """
  What a caller persists per attested key: the key's public key, its
  Counter, the App Attest environment it was attested in, and its current
  Receipt for the next Risk metric fetch.

  Every operation takes a Device and returns one, so a caller stores the
  latest one and passes it back in unchanged:

    1. `AppAttest.Attestation.validate/6` returns it, once per key.
    2. `AppAttest.Assertion.validate/5` takes it and returns it with its
       Counter moved on.
    3. `AppAttest.RiskMetric.fetch/4` takes it and returns it with its
       Receipt moved on to Apple's new one, alongside the risk metric.

  `app_attest` itself never stores it (Corridor ADR 0006): storage belongs
  to the consuming server, which persists what each call returns in place
  of what it passed. Every field is a plain binary, integer or atom, so a
  caller serialises a Device without knowing X.509 or OTP's own key terms.

    * `:public_key` - the attested key's public key, from the Attestation's
      credential certificate, as its DER-encoded SubjectPublicKeyInfo.
    * `:counter` - the last accepted Counter; an Assertion is accepted only
      with a strictly greater one.
    * `:environment` - `:development` or `:production`, the environment the
      key was attested in.
    * `:receipt` - the device's current Receipt: the one the Attestation
      carried in `attStmt.receipt` at first, later the one the previous
      `AppAttest.RiskMetric.fetch/4` returned.
  """

  defstruct [:public_key, :counter, :environment, :receipt]

  @type t :: %__MODULE__{
          public_key: binary(),
          counter: non_neg_integer(),
          environment: AppAttest.AuthenticatorData.environment(),
          receipt: binary()
        }
end
