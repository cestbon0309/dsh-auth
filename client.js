window.__ModuleLoader__.load({
  id: "dsh-auth-gateway",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    // Required services (cordis fiber inject). `connection` is provided by the
    // wire root, so this plugin applies right after it — before the settings
    // surface binds its namespaces.
    const inject = ["connection"];

    /**
     * Browser half of the auth-gateway. The host half fronts the whole web
     * surface behind authentication, but the DSH client still gates its settings
     * plane on `connection.isLoopback` (computed from `location.hostname`, which
     * is a LAN IP here). Mark the session loopback-equivalent so an authenticated
     * remote browser gets the same host settings plane (plugin configuration
     * cards, settings persistence, file open) as a local one.
     */
    function apply(ctx) {
      const connection = ctx.get("connection");
      if (connection && typeof connection === "object" && "isLoopback" in connection) {
        connection.isLoopback = true;
      }
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  }
});
