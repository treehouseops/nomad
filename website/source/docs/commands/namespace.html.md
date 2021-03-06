---
layout: "docs"
page_title: "Commands: namespace"
sidebar_current: "docs-commands-namespace"
description: >
  The namespace command is used to interact with namespaces.
---

# Command: namespace

The `namespace` command is used to interact with namespaces.

~> Namespace commands are new in Nomad 0.7 and are only available with Nomad
Enterprise.

## Usage

Usage: `nomad namespace <subcommand> [options]`

Run `nomad namespace <subcommand> -h` for help on that subcommand. The following
subcommands are available:

- [`namespace apply`][apply] - Create or update a namespace
- [`namespace delete`][delete] - Delete a namespace
- [`namespace inspect`][inspect] - Inspect a namespace
- [`namespace list`][list] - List available namespaces
- [`namespace status`][status] - Display a namespace's status

[apply]: /docs/commands/namespace/apply.html "Create or update a namespace"
[delete]: /docs/commands/namespace/delete.html "Delete a namespace"
[inspect]: /docs/commands/namespace/inspect.html "Inspect a namespace"
[list]: /docs/commands/namespace/list.html "List available namespaces"
[status]: /docs/commands/namespace/status.html "Display a namespace's status"
