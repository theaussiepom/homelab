# Extend a component

A component must define exactly which inputs it accepts and what they do. Do not add an unrestricted options object.

## Contract and resolution

Reuse an existing component when it can express the requirement. In the responsible validator, define the accepted fields, reject unknown keys, and specify defaults, limits and diagnostics that do not disclose private values. Keep parsing in the existing reader and preserve its filesystem restrictions. Resolve references centrally, then test placement, names, resources, identities, readiness dependencies and traffic relationships across the configuration.

Support a complete source file by adding its kind to the existing definition mechanism. Do not add includes, recursive defaults or another parser. Renderers receive validated, resolved values; they must not accept arbitrary user commands or Compose overrides.

## Adapter ownership

Declare only the service, native, network and private-file roles the adapter supports. Register every generated runtime file in the existing application contract and reserve its owner before rendering. Check the files actually emitted against those reservations. Do not mount a path that exposes another app's private directory. Check native accounts, units, configuration paths and numeric IDs across apps that may share a guest.

Preserve storage, process identities, generated-account ownership, existing private roles and credentials, locks, HOLDs and receipts. First-installation support needs initialization that only creates new resources, defined behavior for repeating an operation on HomeLab-managed resources, and explicit limits. Starting the vendor service alone does not prove that commissioning is supported.

## Required examples and evidence

Test the component directly with valid values, defaults, optional fields and intended failures. App and guest unit tests should mock the component using its accepted inputs and outputs. Add integration tests from real source through resolution, packet generation and the receiver for the changed behavior. Controller ownership tests must use real local receipts, Git history, state and app payloads, replacing only native operations with fakes. Identify any provider, parser or credential fakes and explain what they leave untested.

Update the [reference](../reference/README.md), complete examples and descriptions of installation and update support. Rehearse documented commands in a disposable environment. For target validation, retain exact source pins and the evidence from separately authorised target and service checks. The full source checks remain required.

[Contributor index](README.md) · [Testing](testing.md)
