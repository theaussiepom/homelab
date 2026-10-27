"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const code = fs.readFileSync(path.join(__dirname, "../node-red-settings.js"), "utf8");
function load(overrides = {}, original = undefined) {
    const secret = "synthetic-original-secret";
    const settings = original || {credentialSecret: "synthetic-encryption-key", adminAuth: {
        type: "strategy", strategy: {name: "openidconnect", options: {clientSecret: secret, proxy: true}},
        tokens: () => "retained-token-check", users: () => "retained-user-policy"
    }};
    const module = {exports: {}};
    vm.runInNewContext(code, {URL, module, require: (name) => {
        assert.equal(name, "/config/settings.js"); return settings;
    }, process: {env: {NODE_RED_IDENTITY_URL: "https://sso.example.invalid",
        NODE_RED_EXTERNAL_URL: "https://flows.example.invalid", NODE_RED_OIDC_PROVIDER: "nodered",
        NODE_RED_OIDC_CLIENT_ID: "original-client", ...overrides}}});
    return module.exports;
}
test("moves only OIDC origins and preserves private credentials and access policy", () => {
    const settings = load();
    const options = settings.adminAuth.strategy.options;
    assert.equal(options.clientSecret, "synthetic-original-secret");
    assert.equal(settings.credentialSecret, "synthetic-encryption-key");
    assert.equal(settings.adminAuth.tokens(), "retained-token-check");
    assert.equal(settings.adminAuth.users(), "retained-user-policy");
    assert.equal(options.issuer, "https://sso.example.invalid/application/o/nodered/");
    assert.equal(options.callbackURL, "https://flows.example.invalid/auth/strategy/callback/");
});
test("refuses a missing or different restored authentication model", () => {
    for (const settings of [{}, {adminAuth: {type: "credentials"}}]) assert.throws(() => load({}, settings));
});
test("refuses unsafe or missing origins and malformed provider identifiers", () => {
    for (const value of ["", "http://sso.example.invalid", "https://user:secret@sso.example.invalid", "https://sso.example.invalid/path"]) {
        assert.throws(() => load({NODE_RED_IDENTITY_URL: value}));
    }
    assert.throws(() => load({NODE_RED_OIDC_PROVIDER: "../other"}));
});
