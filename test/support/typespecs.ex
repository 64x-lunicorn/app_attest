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
