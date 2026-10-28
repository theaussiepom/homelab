"use strict";
const http = require("node:http");
const settings = require("/config/settings.js");
const request = http.get({hostname: "127.0.0.1", port: settings.uiPort || 1880,
    path: "/auth/login", timeout: 4000}, response => {
    let body = "";
    response.setEncoding("utf8");
    response.on("data", chunk => {
        body += chunk;
        if (body.length > 65536) request.destroy(new Error("Oversized health response"));
    });
    response.on("end", () => {
        try { process.exit(response.statusCode === 200 && JSON.parse(body).type === "strategy" ? 0 : 1); }
        catch { process.exit(1); }
    });
});
request.on("timeout", () => request.destroy(new Error("Health request timeout")));
request.on("error", () => process.exit(1));
