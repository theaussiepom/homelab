"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const code = fs.readFileSync(path.join(__dirname, "../node-red-settings.js"), "utf8");
function load(overrides = {}, original = undefined) {
    const secret = "synthetic-original-secret";
    const settings = original || {uiHost: "172.20.0.8", credentialSecret: "synthetic-encryption-key", adminAuth: {
        type: "strategy", strategy: {name: "openidconnect", options: {clientSecret: secret, proxy: true}},
        tokens: () => "retained-token-check", users: () => "retained-user-policy"
    }};
    const module = {exports: {}};
    vm.runInNewContext(code, {URL, module, require: (name) => {
        if (name === "node:net") return require("node:net");
        assert.equal(name, "/config/settings.js"); return settings;
    }, process: {env: {NODE_RED_IDENTITY_URL: "https://sso.example.invalid",
        NODE_RED_EXTERNAL_URL: "https://flows.example.invalid", NODE_RED_OIDC_PROVIDER: "nodered",
        NODE_RED_OIDC_CLIENT_ID: "original-client", ...overrides}}}, {filename: path.join(__dirname, "../node-red-settings.js")});
    return module.exports;
}
test("moves OIDC origins and the old Docker listener, preserving credentials and access policy", () => {
    const settings = load();
    const options = settings.adminAuth.strategy.options;
    assert.equal(options.clientSecret, "synthetic-original-secret");
    assert.equal(settings.credentialSecret, "synthetic-encryption-key");
    assert.equal(settings.uiHost, "0.0.0.0");
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

test("checks every restored strategy requirement and site input", () => {
    for (const auth of [null, {type: "strategy"}, {type: "strategy", strategy: {}},
        {type: "strategy", strategy: {name: "openidconnect"}},
        {type: "strategy", strategy: {name: "openidconnect", options: {clientSecret: 1}}},
        {type: "strategy", strategy: {name: "openidconnect", options: {clientSecret: ""}}}]) {
        assert.throws(() => load({}, {adminAuth: auth}));
    }
    for (const value of ["https://sso.example.invalid:444", "https://sso.example.invalid/?q=x", "https://sso.example.invalid/#x", "https://sso.example.invalid\n"]) {
        assert.throws(() => load({NODE_RED_EXTERNAL_URL: value}));
    }
    for (const value of ["", "bad/client"]) assert.throws(() => load({NODE_RED_OIDC_CLIENT_ID: value}));
});

test("binds the explicit Apps role while preserving old settings and rejecting unsafe addresses", () => {
    for (const address of ["198.18.40.21", "1.2.3.4", "126.255.255.254", "128.0.0.1",
        "169.253.255.255", "223.255.255.254"])
        assert.equal(load({NODE_RED_WEB_ADDRESS: address}).uiHost, address);
    for (const address of ["", "not-an-address", "::1", "198.18.40.21/24", "0.0.0.0",
        "0.1.2.3", "0.255.255.255", "127.0.0.1", "127.255.255.255", "169.254.1.2",
        "169.254.255.255", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255"])
        assert.throws(() => load({NODE_RED_WEB_ADDRESS: address}));
});
