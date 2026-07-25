/**
 * Frontend smoke tests.
 *
 * Replaces `expect(true).toBe(true)`, which passed unconditionally and
 * verified nothing — a green CI check that cannot fail is worse than no
 * check, because it looks like coverage.
 *
 * Scope is deliberately narrow: this asserts on the API client's shape and
 * its exported surface. It does NOT render components, because that needs
 * jsdom plus a React testing library that isn't currently a dependency —
 * adding one is worthwhile but is a separate change from removing a fake
 * test.
 *
 * What these DO catch:
 *   - an API namespace or method removed/renamed, silently breaking a page
 *   - the intentional-vulnerability surface disappearing by accident
 */

import { auth, products, cart, orders, reviews, profile, admin, vuln } from "../api/client";

describe("API client surface", () => {
  // Each page imports a specific namespace; dropping one breaks that page
  // at runtime with no build-time error, since these are plain objects.
  const expected = {
    auth: ["register", "login", "logout", "me"],
    products: ["list", "get", "search", "create"],
    cart: ["get", "add", "remove", "clear"],
    orders: ["list", "get", "checkout"],
    reviews: ["list", "create"],
    profile: ["get", "update"],
    admin: ["stats", "users", "exec"],
    vuln: ["fetch", "upload"],
  };
  const namespaces = { auth, products, cart, orders, reviews, profile, admin, vuln };

  test.each(Object.entries(expected))(
    "%s exposes all its methods",
    (name, methods) => {
      const ns = namespaces[name];
      expect(ns).toBeDefined();
      methods.forEach((m) => {
        expect(typeof ns[m]).toBe("function");
      });
    }
  );
});

describe("intentional vulnerability surface", () => {
  // README documents these as planted vulnerabilities and the security
  // pipeline reports them every run. If someone removes them the app gets
  // safer and the demo silently loses findings, so assert they persist on
  // purpose — the same guard the backend suite applies to the SQLi route.
  test("admin.exec (command injection demo) is still exposed", () => {
    expect(typeof admin.exec).toBe("function");
  });

  test("vuln.fetch (SSRF demo) is still exposed", () => {
    expect(typeof vuln.fetch).toBe("function");
  });
});
