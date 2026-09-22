# Scenarios tagged `:pending` (test/integration/) name behaviour no ticket has
# built yet. Excluding them here is what keeps the required `Test` check
# green; the advisory `Pending scenarios` check runs them for real with
# `mix test --only pending`, so each one visibly fails for the missing
# behaviour instead of silently not running at all.
ExUnit.start(exclude: [:pending])
