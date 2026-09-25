defmodule AppAttest.PublicApiTest do
  use ExUnit.Case, async: true

  alias AppAttest.{Device, Typespecs}

  # What a Hex reader sees: the library's own modules (those under `lib/`,
  # not the test support compiled alongside them) whose docs are not hidden
  # with `@moduledoc false`.
  defp documented_modules do
    for module <- library_modules(),
        {:docs_v1, _anno, _language, _format, moduledoc, _metadata, _docs} =
          Code.fetch_docs(module),
        moduledoc != :hidden,
        do: module
  end

  defp library_modules do
    {:ok, modules} = :application.get_key(:app_attest, :modules)

    Enum.filter(modules, fn module ->
      source = to_string(module.module_info(:compile)[:source])
      String.contains?(source, "/lib/app_attest/")
    end)
  end

  describe "documented modules" do
    test "are Attestation, Assertion, RiskMetric, Receipt, RootCertificate and Device only" do
      assert Enum.sort(documented_modules()) ==
               Enum.sort([
                 AppAttest.Attestation,
                 AppAttest.Assertion,
                 AppAttest.RiskMetric,
                 AppAttest.Receipt,
                 AppAttest.RootCertificate,
                 AppAttest.Device
               ])
    end

    test "name the authenticator data module in none of their typespecs" do
      for module <- documented_modules() do
        refute AppAttest.AuthenticatorData in Typespecs.referenced_modules(module),
               "#{inspect(module)} references AppAttest.AuthenticatorData in a typespec"
      end
    end
  end

  describe "Device.environment/0" do
    test "is Apple's development or production environment" do
      assert Typespecs.union_atoms(Device, :environment) == [:development, :production]
    end

    test "is documented" do
      {:docs_v1, _anno, _language, _format, _moduledoc, _metadata, docs} =
        Code.fetch_docs(Device)

      assert [%{"en" => doc}] =
               for({{:type, :environment, 0}, _anno, _signature, doc, _meta} <- docs, do: doc)

      assert doc =~ "environment"
    end
  end
end
