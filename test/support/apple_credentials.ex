defmodule AppAttest.AppleCredentials do
  @moduledoc """
  The real Apple DeviceCheck key that `AppAttest.RiskMetricAppleTest` sends
  to Apple's own risk-metric endpoint, read from the environment so that no
  key material ever lives in the repository.

  Three variables, all of them needed:

    * `APPLE_DEVICECHECK_KEY_FILE` - the path to the `.p8` file downloaded
      from the Apple Developer portal. This is the local form; keep the file
      outside the repository and readable only by yourself.
    * `APPLE_DEVICECHECK_KEY` - the same file's *contents*, for CI, where a
      secret arrives as a value rather than a path. Takes precedence over
      the path when both are set.
    * `APPLE_DEVICECHECK_KEY_ID` - the DeviceCheck key identifier Apple
      assigned that key (the JWT's `kid`), not a device's Key ID.
    * `APPLE_TEAM_ID` - the Apple Developer Team ID that owns it.

  `available?/0` is false when any of them is missing, and `test_helper.exs`
  then excludes the tests that need them, so a fresh clone with no Apple
  account stays green. `CONTRIBUTING.md` describes the setup.
  """

  @key_contents "APPLE_DEVICECHECK_KEY"
  @key_file "APPLE_DEVICECHECK_KEY_FILE"
  @key_id "APPLE_DEVICECHECK_KEY_ID"
  @team_id "APPLE_TEAM_ID"

  @doc "Whether the environment carries a full set of Apple credentials."
  @spec available?() :: boolean()
  def available? do
    (System.get_env(@key_contents) || System.get_env(@key_file)) != nil and
      System.get_env(@key_id) != nil and System.get_env(@team_id) != nil
  end

  @doc """
  The real DeviceCheck key, in the shape `AppAttest.RiskMetric.fetch/5`
  takes. Raises unless `available?/0`, which is what the tests that call
  this are excluded on.
  """
  @spec device_check_key!() :: AppAttest.RiskMetric.device_check_key()
  def device_check_key! do
    %{
      key_id: System.fetch_env!(@key_id),
      team_id: System.fetch_env!(@team_id),
      private_key: X509.PrivateKey.from_pem!(private_key_pem!())
    }
  end

  defp private_key_pem! do
    case System.get_env(@key_contents) do
      nil -> @key_file |> System.fetch_env!() |> Path.expand() |> File.read!()
      contents -> contents
    end
  end
end
