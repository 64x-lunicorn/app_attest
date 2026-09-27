defmodule AppAttest.MixProject do
  use Mix.Project

  @source_url "https://github.com/64x-lunicorn/app_attest"

  def project do
    [
      app: :app_attest,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer()
    ]
  end

  def application do
    [
      # :inets (for :httpc) and :ssl: AppAttest.RiskMetric's own HTTP call to
      # Apple's real risk-metric endpoint. Both ship with Erlang/OTP
      # itself, so this adds no new Hex dependency.
      extra_applications: [:logger, :inets, :ssl]
    ]
  end

  defp deps do
    [
      {:cbor, "~> 1.0"},
      {:x509, "~> 0.9"},
      {:ex_doc, "~> 0.40", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    "Validates Apple App Attest attestations and assertions, including the " <>
      "certificate chain, nonce, App ID hash, replay-safe Counter and Apple's " <>
      "per-device Risk metric."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs .formatter.exs README.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CONTEXT.md", "LICENSE"],
      assets: %{"docs/assets" => "docs/assets"},
      # `mix ci` builds the docs in the test env, which also compiles
      # test/support; its helpers are not part of the library.
      filter_modules: fn _module, %{source_path: path} ->
        not String.starts_with?(to_string(path), Path.expand("test/support"))
      end
    ]
  end

  # One fixed PLT location, so the gate's `mix dialyzer` (dev env) and
  # `mix ci` (test env) share it instead of each building its own under
  # `_build/<env>`.
  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_local_path: "priv/plts"
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
        "test",
        "docs --warnings-as-errors",
        # `hex.build` and `hex.audit` each in their own process: compiling
        # prunes the Hex archive's code path, so Hex tasks are no longer
        # found later in the same Mix run.
        "cmd mix hex.build",
        "credo --strict",
        "dialyzer",
        "cmd mix hex.audit",
        "deps.audit"
      ]
    ]
  end

  def cli do
    [preferred_envs: [ci: :test]]
  end
end
