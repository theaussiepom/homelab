# Glossary

| Term | Meaning |
| --- | --- |
| Adapter | Framework code that generates configuration, prepares inputs and runs deployment for one application family |
| App | Named profile instance placed on a guest |
| AppPayload | Protected files for one selected app, fixed for the operation, with evidence identifying its private input roles |
| Binding | A choice that connects an app's requirement to a resource, such as a storage role to a guest volume. During deployment, a separate binding record connects the exact source, VMID and selected static inputs and accepts only its defined fields. |
| Canonical receipt | Pointer to the receipt for the latest successful normal operation |
| Component | A reusable type with defined fields, validation and explicit references |
| Context | A declaration of the provider endpoint and the controller's required trust inputs, credential references and paths |
| Exposure | Declared DNS name or HTTPS frontend route |
| Fresh | A lifecycle policy that permits supported creation when no backend or prior owner exists. Keep the same policy for supported later updates to that HomeLab installation; it cannot import another installation. |
| Guest | An allocated Debian LXC with stable network interfaces, storage and identity |
| HOLD | A protected marker identifying a failed or active operation; it cannot be cleared simply to retry |
| Immutable receipt | A preserved record of one successful operation, separate from the pointer to the latest success |
| Library | Versioned profiles, templates and reusable definitions |
| Lowering | Converting a completed plan into files containing deployment inputs for engines and receivers |
| Native | Actual operating-system/service/infrastructure behavior, beyond source compilation |
| Ordinary run | The normal protected deployment workflow, which preserves existing HomeLab ownership and cannot import another installation |
| Policy | An explicit named declaration for network access, transport, TLS, middleware or authentication |
| Profile | Library declaration of one adapter's roles and requirements |
| Readiness | An explicit supported dependency that controls startup or configuration order; a value reference alone creates no dependency |
| Retained | A lifecycle policy requiring an installation already managed by HomeLab; it cannot adopt another installation |
| Site | Your configuration of allocations, guest and app placement, and bindings using the defined types |
| Source pin | A digest identifying the exact source snapshot the compiler read |
| Template | Complete guest defaults, before explicit guest field overrides |

[Documentation index](README.md)
