defmodule AppAttest.MixProject do
  use Mix.Project

  def project do
    [
      app: :app_attest,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:cbor, "~> 1.0"},
      {:x509, "~> 0.9"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp aliases do
    [
      ci: [
        "format --check-formatted",
        "deps.unlock --check-unused",
        "compile --warnings-as-errors",
        "test"
      ]
    ]
  end

  def cli do
    [preferred_envs: [ci: :test]]
  end
end
