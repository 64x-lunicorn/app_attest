defmodule AppAttest.Typespecs do
  @moduledoc """
  Reads a module's own declared types back off its compiled BEAM, so a test
  can assert that a documented type lists exactly what the code returns.

  `AppAttest.Attestation.rejection/0` and `AppAttest.Assertion.rejection/0`
  are the contract a caller matches on, and nothing else in a compile or a
  test run notices when a new rejection reason is returned but never
  declared — which is how `:cbor_match_error` and
  `:invalid_authenticator_data` came to leak through undeclared in the
  first place.
  """

  @doc """
  Every atom the union type `name` of `module` declares, in declaration
  order, with any type it refers to in another module resolved in place.
  """
  @spec union_atoms(module(), atom()) :: [atom()]
  def union_atoms(module, name), do: atoms(fetch_type(module, name))

  @doc """
  Every module `module`'s own types and function specs refer to by a
  remote type (`SomeModule.t()`), so a test can assert which modules a
  public contract names.
  """
  @spec referenced_modules(module()) :: [module()]
  def referenced_modules(module) do
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

  defp atoms({:type, _line, :union, members}), do: Enum.flat_map(members, &atoms/1)
  defp atoms({:atom, _line, atom}), do: [atom]

  defp atoms({:remote_type, _line, [{:atom, _, module}, {:atom, _, name}, []]}) do
    atoms(fetch_type(module, name))
  end

  defp fetch_type(module, name) do
    {:ok, types} = Code.Typespec.fetch_types(module)
    {:type, {^name, definition, []}} = Enum.find(types, &match?({:type, {^name, _, []}}, &1))
    definition
  end
end
