"use strict";
const assert = require("node:assert/strict");
const {EventEmitter} = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const code = fs.readFileSync(path.join(__dirname, "../node-red-healthcheck.js"), "utf8");

function check(status, body, timeout = false, uiPort = 1880) {
    const request = new EventEmitter();
    let callback, options, result;
    request.destroy = error => request.emit("error", error);
    const http = {get: (value, handler) => {options = value; callback = handler; return request;}};
    vm.runInNewContext(code, {require: name => {
        if (name === "node:http") return http;
        assert.equal(name, "/config/settings.js"); return {uiPort, uiHost: "172.20.0.8"};
    }, process: {exit: value => {result = value;}}}, {filename: path.join(__dirname, "../node-red-healthcheck.js")});
    if (timeout) request.emit("timeout");
    else {
        const response = new EventEmitter(); response.setEncoding = () => {};
        response.statusCode = status; callback(response);
        response.emit("data", body); response.emit("end");
    }
    return {result, options};
}

test("checks the guest loopback login rather than the old Docker address", () => {
    const {result, options} = check(200, '{"type":"strategy"}');
    assert.equal(result, 0); assert.equal(options.hostname, "127.0.0.1");
    assert.equal(options.path, "/auth/login"); assert.equal(options.port, 1880);
});
test("fails on a missing login strategy, bad status, invalid JSON or timeout", () => {
    for (const [status, body] of [[200, '{}'], [503, '{"type":"strategy"}'], [200, 'not json']]) {
        assert.equal(check(status, body).result, 1);
    }
    assert.equal(check(200, '', true).result, 1);
});

test("uses the default port and refuses oversized replies", () => {
    assert.equal(check(200, '{"type":"strategy"}', false, undefined).options.port, 1880);
    assert.equal(check(200, '{"type":"strategy"}', false, 0).options.port, 1880);
    assert.equal(check(200, "x".repeat(65537)).result, 1);
});
