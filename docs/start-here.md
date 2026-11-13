# Start here

Start with the result you want: applications running on guests whose placement, addresses and storage you control. HomeLab represents that desired arrangement as a **site**, a YAML file in your own configuration directory or repository. A **library** supplies reusable application profiles and guest defaults. The **framework** checks the combination and prepares the inputs used by deployment.

## Choose a useful first result

| Your goal | Begin here | What you will produce |
| --- | --- | --- |
| Choose real applications and design my own homelab | [HomeLab Stack getting started](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) | A site using the library's supported profiles, their prerequisites and your allocations |
| Learn to write and inspect the configuration language first | [Your first configuration](guides/first-configuration.md) | A complete personalised practice site, then a packet showing its actual guest and app settings |
| Use an existing site with real infrastructure | [Prepare a deployment](guides/prepare-deployment.md) | Reviewed input locations, compatible revisions and a clear statement of what installation supports |
| Prepare recovery before the first deployment | [Set up backups](backup/README.md) | PBS storage, independently recoverable keys, API access, configuration and a restore checklist |
| Maintain an existing HomeLab installation | [Later deployments](operations/verify-and-maintain.md#later-deployments) | A change reviewed against current ownership records and service observations |

The framework walkthrough uses a small maintained library so you can concentrate on configuration. Its Unbound profile publishes only inside its guest on loopback; the lesson is not a household DNS installation. Application choice and supported compositions belong in the stack journey. You do not need to finish a glossary before following either route; the [model](concepts.md) and [glossary](glossary.md) are available when you need a definition.

## Choose the owner before choosing a setting

In a site, `guests.resolver` names a guest and `apps.recursive_a.guest: resolver` places an app on it. Those names are references between declarations. The profile selected by `apps.recursive_a.profile` comes from the library, and the framework determines what that profile and binding mean.

| You want to change… | Owner | Read next |
| --- | --- | --- |
| What a field accepts or how it compiles | Framework | [Contract reference](reference/README.md) |
| Which app profile, software or defaults are selected | Compatible library | [Library contract](reference/library.md) and that library's catalogue |
| Guest placement, addresses, paths or secret-source references | Your site configuration | [Site contract](reference/site.md) |
| An existing installation's actual resources/services | Your protected deployment procedure | [Preparation](guides/prepare-deployment.md) and [lifecycle](reference/lifecycle.md) |

A profile selects the fields and capabilities supported by its adapter; it cannot supply arbitrary Compose overrides. A source reference includes one complete declaration of the specified type; it cannot overlay partial values. The walkthrough introduces both after you have a complete working site.

## Prepare for the offline tutorial

You need Git, Python 3.12 or newer, a text editor and basic familiarity with YAML indentation and IPv4 addresses. Begin in a reviewed checkout of this framework; [the walkthrough](guides/first-configuration.md#prepare-an-isolated-workspace) includes a clone route and isolated environment setup. No Proxmox host or credentials are required.

The tutorial's library, image catalogue and starting site live together in the same framework checkout. Its dependencies are installed from that checkout's `requirements.lock.txt` with `--require-hashes`. The source reader uses the pinned PyYAML dependency; there are no custom functions or tags to learn.

For an application configuration using homelab-stack, use the framework revision selected by that library. An unrelated current framework branch is a different compatibility choice. See [compatible source selection](guides/prepare-deployment.md#select-compatible-source).

## Know what each result means

The first milestone is a file you can explain and a compiler result whose guest settings match your choices. Parsing, validation and generation of deployment inputs inspect source; they do not establish host access, image availability or a running service. Preparation then checks real facts and binds the required protected inputs, deployment executes the supported phases, and service verification checks what actually works. The [evidence guide](concepts/evidence.md) names each boundary.

Continue with [your first configuration](guides/first-configuration.md), then [prepare real inputs](guides/prepare-deployment.md). Return to the [documentation index](README.md) for reference and operating routes.
