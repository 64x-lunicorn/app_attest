defmodule AppAttest.PublicApiTest do
  use ExUnit.Case, async: true

  alias AppAttest.Device

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
    test "are Attestation, Assertion, RiskMetric, Receipt, Trust, RootCertificate and Device only" do
      assert Enum.sort(documented_modules()) ==
               Enum.sort([
                 AppAttest.Attestation,
                 AppAttest.Assertion,
                 AppAttest.RiskMetric,
                 AppAttest.Receipt,
                 AppAttest.Trust,
                 AppAttest.RootCertificate,
                 AppAttest.Device
               ])
    end

    test "name the authenticator data module in none of their typespecs" do
      for module <- documented_modules() do
        refute AppAttest.AuthenticatorData in referenced_modules(module),
               "#{inspect(module)} references AppAttest.AuthenticatorData in a typespec"
      end
    end
  end

  describe "rejection vocabularies" do
    # A caller matches on a documented module's `rejection/0`, so every atom
    # it declares is minted in that module's own code, and every atom that
    # code returns in an `{:error, reason}` is declared: the contract a
    # caller reads is the one the code returns, read off both.
    test "each documented module returns exactly the atoms its rejection type declares" do
      for module <- documented_modules(), declares_rejection?(module) do
        assert Enum.sort(returned_error_atoms(module)) ==
                 Enum.sort(declared_atoms(module, :rejection)),
               "#{inspect(module)} returns #{inspect(Enum.sort(returned_error_atoms(module)))} " <>
                 "but its rejection/0 declares #{inspect(Enum.sort(declared_atoms(module, :rejection)))}"
      end
    end

    test "no hidden module returns an atom of a public rejection vocabulary" do
      public_atoms =
        for module <- documented_modules(),
            declares_rejection?(module),
            atom <- declared_atoms(module, :rejection),
            do: atom

      for module <- library_modules() -- documented_modules() do
        leaked = Enum.filter(returned_error_atoms(module), &(&1 in public_atoms))

        assert leaked == [],
               "#{inspect(module)} returns #{inspect(leaked)}, minted by a public rejection/0"
      end
    end
  end

  describe "Device.environment/0" do
    test "is Apple's development or production environment" do
      assert declared_atoms(Device, :environment) == [:development, :production]
    end

    test "is documented" do
      {:docs_v1, _anno, _language, _format, _moduledoc, _metadata, docs} =
        Code.fetch_docs(Device)

      assert [%{"en" => doc}] =
               for({{:type, :environment, 0}, _anno, _signature, doc, _meta} <- docs, do: doc)

      assert doc =~ "environment"
    end
  end

  # Every atom the union type `name` of `module` declares, in declaration
  # order; members that are not atoms, such as RiskMetric's error tuples,
  # are skipped.
  defp declared_atoms(module, name) do
    module |> fetch_type(name) |> union_members() |> Enum.flat_map(&atom_member/1)
  end

  defp declares_rejection?(module) do
    {:ok, types} = Code.Typespec.fetch_types(module)
    Enum.any?(types, &match?({:type, {:rejection, _definition, []}}, &1))
  end

  defp fetch_type(module, name) do
    {:ok, types} = Code.Typespec.fetch_types(module)
    {:type, {^name, definition, []}} = Enum.find(types, &match?({:type, {^name, _, []}}, &1))
    definition
  end

  defp union_members({:type, _line, :union, members}), do: members
  defp union_members(single), do: [single]

  defp atom_member({:atom, _line, atom}), do: [atom]
  defp atom_member(_not_an_atom), do: []

  # Every atom `reason` of an `{:error, reason}` tuple `module`'s compiled
  # code builds, read off its abstract code: clause bodies only, so an
  # `{:error, reason}` a clause merely matches (a callee's reason being
  # translated) does not count as one the module returns.
  defp returned_error_atoms(module) do
    {_module, beam, _path} = :code.get_object_code(module)

    {:ok, {_, [abstract_code: {:raw_abstract_v1, forms}]}} =
      :beam_lib.chunks(beam, [:abstract_code])

    for {:function, _line, _name, _arity, clauses} <- forms,
        atom <- built_error_atoms(clauses),
        uniq: true,
        do: atom
  end

  defp built_error_atoms({:tuple, _line, [{:atom, _, :error}, {:atom, _, reason}]}), do: [reason]
  defp built_error_atoms({:clause, _line, _patterns, _guards, body}), do: built_error_atoms(body)
  defp built_error_atoms({:match, _line, _pattern, expression}), do: built_error_atoms(expression)
  defp built_error_atoms(term) when is_tuple(term), do: built_error_atoms(Tuple.to_list(term))
  defp built_error_atoms(term) when is_list(term), do: Enum.flat_map(term, &built_error_atoms/1)
  defp built_error_atoms(_leaf), do: []

  # Every module `module`'s own types and function specs refer to by a
  # remote type (`SomeModule.t()`), so a test can assert which modules a
  # public contract names.
  defp referenced_modules(module) do
    {:ok, types} = Code.Typespec.fetch_types(module)
    {:ok, specs} = Code.Typespec.fetch_specs(module)

    (types ++ specs)
    |> remote_modules()
    |> Enum.uniq()
  end

  defp remote_modules({:remote_type, _line, [{:atom, _, module}, _name, arguments]}) do
    [module | remote_modules(arguments)]
  end

  defp remote_modules(term) when is_tuple(term), do: remote_modules(Tuple.to_list(term))
  defp remote_modules(term) when is_list(term), do: Enum.flat_map(term, &remote_modules/1)
  defp remote_modules(_leaf), do: []
end
