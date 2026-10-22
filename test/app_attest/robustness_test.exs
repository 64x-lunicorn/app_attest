defmodule AppAttest.RobustnessTest do
  @moduledoc """
  Random damage to real Apple bytes, in bulk: every outcome is one the
  module documents, never a raise, never a crash. The single-byte and
  truncation tests of each module prove the same for one position at a
  time; this one combines flips, overwrites, insertions, deletions and
  trailing junk at random positions, with a fixed seed so a failure
  reproduces.
  """

  use ExUnit.Case, async: true

  alias AppAttest.{Assertion, Attestation, Device, Fixtures, Receipt, Trust}

  @mutations 300

  @attestation_rejections [
    :invalid_attestation,
    :untrusted_root,
    :certificate_expired,
    :nonce_mismatch,
    :key_id_mismatch,
    :invalid_authenticator_data,
    :app_id_mismatch,
    :counter_not_zero,
    :unrecognized_environment,
    :environment_mismatch
  ]

  @assertion_rejections [
    :invalid_device,
    :environment_mismatch,
    :invalid_assertion,
    :invalid_authenticator_data,
    :invalid_signature,
    :app_id_mismatch,
    :counter_not_increasing
  ]

  @receipt_rejections [:untrusted_receipt, :certificate_expired, :invalid_receipt]

  test "Apple's real Attestation, randomly damaged, is accepted or rejected for a documented reason" do
    each_mutation(Fixtures.attestation(), {1, 2, 3}, fn damaged ->
      result =
        Attestation.validate(
          damaged,
          Fixtures.key_id(),
          Fixtures.challenge(),
          Fixtures.app_id(),
          Trust.apple(),
          :development,
          at: Fixtures.attestation_time()
        )

      assert match?({:ok, %Device{}}, result) or
               match?({:error, reason} when reason in @attestation_rejections, result),
             "#{inspect(result)} for #{inspect(damaged, limit: 20)}"
    end)
  end

  test "a real device's Assertion, randomly damaged, is accepted or rejected for a documented reason" do
    device = %Device{
      public_key: Fixtures.real_assertion_public_key(),
      counter: 0,
      environment: :production,
      receipt: "the-device's-current-receipt"
    }

    each_mutation(Fixtures.real_assertion(), {4, 5, 6}, fn damaged ->
      result =
        Assertion.validate(
          damaged,
          Fixtures.real_assertion_client_data(),
          Fixtures.real_assertion_app_id(),
          device,
          :production
        )

      assert match?({:ok, %Device{}}, result) or
               match?({:error, reason} when reason in @assertion_rejections, result),
             "#{inspect(result)} for #{inspect(damaged, limit: 20)}"
    end)
  end

  test "Apple's real Receipt, randomly damaged, is verified or rejected for a documented reason" do
    each_mutation(Fixtures.attestation_receipt(), {7, 8, 9}, fn damaged ->
      result = Receipt.verify(damaged, Trust.apple(), at: Fixtures.attestation_time())

      assert match?({:ok, %Receipt{}}, result) or
               match?({:error, reason} when reason in @receipt_rejections, result),
             "#{inspect(result)} for #{inspect(damaged, limit: 20)}"
    end)
  end

  defp each_mutation(genuine, seed, check) do
    Enum.reduce(1..@mutations, :rand.seed_s(:exsss, seed), fn _, state ->
      {damaged, state} = mutate(genuine, state)
      check.(damaged)
      state
    end)
  end

  # One random change: flipped bits, an overwritten, inserted or deleted
  # slice, a truncation, or junk before or after.
  defp mutate(bin, state) do
    {kind, state} = :rand.uniform_s(6, state)
    {position, state} = :rand.uniform_s(byte_size(bin), state)
    position = position - 1
    {length, state} = :rand.uniform_s(16, state)
    length = min(length, byte_size(bin) - position)
    {junk, state} = random_bytes(length, state)
    <<before::binary-size(position), slice::binary-size(length), rest::binary>> = bin

    case kind do
      1 -> {before <> flip(slice, junk) <> rest, state}
      2 -> {before <> junk <> rest, state}
      3 -> {before <> junk <> slice <> rest, state}
      4 -> {before <> rest, state}
      5 -> {before, state}
      6 -> {if(position < 8, do: junk <> bin, else: bin <> junk), state}
    end
  end

  defp flip(slice, mask) do
    :crypto.exor(slice, binary_part(mask, 0, byte_size(slice)))
  end

  defp random_bytes(count, state) do
    {bytes, state} =
      Enum.map_reduce(1..count, state, fn _, state ->
        {byte, state} = :rand.uniform_s(256, state)
        {byte - 1, state}
      end)

    {:binary.list_to_bin(bytes), state}
  end
end
