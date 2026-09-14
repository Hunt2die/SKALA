using Workerd = import "/workerd/workerd.capnp";

# Real Workers APIs with deterministic outbound responses; no external network or listener.
const config :Workerd.Config = (
  services = [
    (name = "skala", worker = (
      compatibilityDate = "2026-09-14",
      globalOutbound = "fixture",
      modules = [
        (name = "tests/worker-runtime.mjs", esModule = embed "worker-runtime.mjs"),
        (name = "worker/diagnostics.mjs", esModule = embed "../worker/diagnostics.mjs"),
        (name = "worker/handler.mjs", esModule = embed "../worker/handler.mjs"),
        (name = "worker/target.mjs", esModule = embed "../worker/target.mjs"),
        (name = "worker/cloudflare.mjs", esModule = embed "../worker/cloudflare.mjs"),
        (name = "worker/registration.mjs", esModule = embed "../worker/registration.mjs")
      ]
    )),
    (name = "fixture", worker = (
      compatibilityDate = "2026-09-14",
      modules = [(name = "fixture.mjs", esModule = embed "worker-outbound.mjs")]
    ))
  ]
);
