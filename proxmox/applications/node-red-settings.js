"use strict";

// Keep the existing palette, credential key, API-token checks, user policy and
// flows. Only the selected native OIDC endpoints move with the site hostname.
const settings = require("/config/settings.js");
const auth = settings.adminAuth;
if (!auth || auth.type !== "strategy" || !auth.strategy ||
    auth.strategy.name !== "openidconnect" || !auth.strategy.options ||
    typeof auth.strategy.options.clientSecret !== "string" || !auth.strategy.options.clientSecret) {
    throw new Error("Restore the existing Node-RED Authentik OIDC settings first");
}
function required(name) {
    const value = process.env[name];
    if (!value || /[\r\n\0]/.test(value)) throw new Error("Missing Node-RED OIDC site setting");
    return value;
}
function origin(name) {
    const value = required(name);
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port ||
        url.pathname !== "/" || url.search || url.hash) {
        throw new Error("Node-RED OIDC needs an HTTPS origin");
    }
    return url.origin;
}
const identity = origin("NODE_RED_IDENTITY_URL");
const external = origin("NODE_RED_EXTERNAL_URL");
const provider = required("NODE_RED_OIDC_PROVIDER");
const client = required("NODE_RED_OIDC_CLIENT_ID");
if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(provider) || !/^[A-Za-z0-9_-]{1,256}$/.test(client)) {
    throw new Error("Invalid Node-RED OIDC provider or client identifier");
}
Object.assign(auth.strategy.options, {
    issuer: `${identity}/application/o/${provider}/`,
    authorizationURL: `${identity}/application/o/authorize/`,
    tokenURL: `${identity}/application/o/token/`,
    userInfoURL: `${identity}/application/o/userinfo/`,
    clientID: client,
    callbackURL: `${external}/auth/strategy/callback/`
});
module.exports = settings;
