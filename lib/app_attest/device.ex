defmodule AppAttest.Device do
  @moduledoc """
  What a caller persists per attested key: the key's public key, its
  Counter, the App Attest environment it was attested in, and its current
  receipt for the next Risk metric fetch.

  `AppAttest.Attestation.validate/6` returns one; every
  `AppAttest.Assertion.validate/5` takes the stored one and returns it with
  the Counter moved on; `AppAttest.RiskMetric.fetch/5` takes its `receipt`
  and returns the next one to store in its place. `app_attest` itself never
  stores it (Corridor ADR 0006): storage belongs to the consuming server, so
  the caller persists the struct and passes it back in.

    * `:public_key` - the attested key's public key, from the Attestation's
      credential certificate.
    * `:counter` - the last accepted Counter; an Assertion is accepted only
      with a strictly greater one.
    * `:environment` - `:development` or `:production`, the environment the
      key was attested in.
    * `:receipt` - the device's current receipt: the one the Attestation
      carried in `attStmt.receipt` at first, later the one the previous
      `AppAttest.RiskMetric.fetch/5` returned.
  """

  defstruct [:public_key, :counter, :environment, :receipt]

  @type t :: %__MODULE__{
          public_key: :public_key.public_key(),
          counter: non_neg_integer(),
          environment: AppAttest.AuthenticatorData.environment(),
          receipt: binary()
        }
end
