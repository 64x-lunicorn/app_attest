defmodule AppAttest.Envelope do
  @moduledoc false

  # The one place that knows the `cbor` package (#10). Apple's SDK hands both
  # an Attestation and an Assertion over as a CBOR object; everything this
  # module decodes comes back as plain binaries and maps, and every way a
  # raw object can fail to decode, or decode into the wrong shape, comes back
  # as `:invalid_attestation` or `:invalid_assertion`. So neither
  # `AppAttest.Attestation.rejection/0` nor `AppAttest.Assertion.rejection/0`
  # names a `cbor` atom a caller would have to match on, and upgrading or
  # swapping the `cbor` package changes this module only.

  @typedoc """
  A decoded `apple-appattest` Attestation object: its raw `authData`, its
  leaf-first `x5c` certificate chain (DER), and the raw receipt it carries
  in `attStmt.receipt` (#11).
  """
  @type attestation :: %{
          auth_data: binary(),
          chain: [AppAttest.RootCertificate.der(), ...],
          receipt: binary()
        }

  @typedoc "A decoded Assertion object: its raw `signature` and `authenticatorData`."
  @type assertion :: %{signature: binary(), auth_data: binary()}

  @doc false
  @spec decode_attestation(term()) :: {:ok, attestation()} | {:error, :invalid_attestation}
  def decode_attestation(attestation_object) do
    with {:ok, decoded} <- decode(attestation_object),
         {:ok, attestation} <- unwrap_attestation(decoded) do
      {:ok, attestation}
    else
      :error -> {:error, :invalid_attestation}
    end
  end

  @doc false
  @spec decode_assertion(term()) :: {:ok, assertion()} | {:error, :invalid_assertion}
  def decode_assertion(assertion_object) do
    with {:ok, decoded} <- decode(assertion_object),
         {:ok, assertion} <- unwrap_assertion(decoded) do
      {:ok, assertion}
    else
      :error -> {:error, :invalid_assertion}
    end
  end

  # `CBOR.decode/1` reports malformed or non-binary input with one of its
  # own five error atoms; all of them collapse to `:error` here, so none
  # leaves this module (#10).
  # Trailing bytes after the object are ignored, as they always were.
  defp decode(object) do
    case CBOR.decode(object) do
      {:ok, decoded, _rest} -> {:ok, decoded}
      {:error, _cbor_reason} -> :error
    end
  end

  # Everything a genuine Attestation object carries, taken apart in one
  # place: anything else is not an `apple-appattest` attestation object and
  # is rejected rather than raising (#212).
  defp unwrap_attestation(%{
         "fmt" => "apple-appattest",
         "attStmt" => att_stmt,
         "authData" => auth_data_tag
       })
       when is_map(att_stmt) do
    with {:ok, auth_data} <- unwrap_bytes(auth_data_tag),
         {:ok, chain} <- unwrap_chain(Map.get(att_stmt, "x5c")),
         {:ok, receipt} <- unwrap_bytes(Map.get(att_stmt, "receipt")) do
      {:ok, %{auth_data: auth_data, chain: chain, receipt: receipt}}
    end
  end

  defp unwrap_attestation(_not_an_apple_attestation), do: :error

  defp unwrap_assertion(%{"signature" => signature_tag, "authenticatorData" => auth_data_tag}) do
    with {:ok, signature} <- unwrap_bytes(signature_tag),
         {:ok, auth_data} <- unwrap_bytes(auth_data_tag) do
      {:ok, %{signature: signature, auth_data: auth_data}}
    end
  end

  defp unwrap_assertion(_not_an_assertion), do: :error

  # A non-empty list of CBOR byte strings, leaf first; anything else is
  # `:error` rather than a crash (#212).
  defp unwrap_chain([_first | _rest] = x5c) do
    unwrapped = Enum.map(x5c, &unwrap_bytes/1)

    if Enum.all?(unwrapped, &match?({:ok, _der}, &1)) do
      {:ok, Enum.map(unwrapped, fn {:ok, der} -> der end)}
    else
      :error
    end
  end

  defp unwrap_chain(_not_a_certificate_chain), do: :error

  # The `cbor` package wraps every decoded CBOR byte string (the format
  # Apple uses for authData, each x5c certificate, the receipt, an
  # Assertion's own signature and authenticatorData) in a `%CBOR.Tag{tag: :bytes, value:
  # binary}` rather than handing back the raw binary (its own README
  # explains why). Anything else — a CBOR text string, a number, a missing
  # key's `nil` — is `:error` rather than a crash (#212): a caller's own
  # field is exactly what a forged object gets wrong.
  defp unwrap_bytes(%CBOR.Tag{tag: :bytes, value: value}) when is_binary(value), do: {:ok, value}
  defp unwrap_bytes(_not_a_cbor_byte_string), do: :error
end
