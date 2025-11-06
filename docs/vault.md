# syc Vaults

The syc CLI and future library lookups expect a **vault** directory that holds
private key material and configuration metadata. By default the vault is
`~/.syc`, but you can point commands at an alternate location in two ways:

- Pass `--vault /path/to/vault` on the command line.
- Set the `SYC_VAULT` environment variable before invoking `syc`.

## Suggested Layout

```
~/.syc/
├── keys/                 # identity key stores (per identity)
├── config/               # JSON/TOML blobs describing datasite mappings
└── logs/                 # optional diagnostics
```

The exact structure is still evolving; the goal is to give every datasite a
defined mapping between its encrypted tree and a corresponding shadow directory
without leaking plaintext into the synced locations. The CLI consumes
`config/datasite.json` to discover both the encrypted root (`encrypted_root`)
and the shadow location (`shadow_root`), so keeping this file up to date allows
commands to operate without additional flags.

For testing multiple SyftBox instances on the same machine, create a dedicated
vault per instance and invoke the CLI with `--vault`. That keeps identity keys,
manifest files, and shadow data mappings totally isolated.

## Datasite Shadow Mapping

Vault configuration files will describe how a SyftBox `data_dir` maps its
synced `datasites/<identity>` trees to unsynced plaintext shadow directories. A suggested
layout is:

```
<data_dir>/
├── datasites/           # SyftBox-managed (ciphertext + public metadata)
└── unencrypted/         # Shadow directory for decrypted blobs (not synced)
```
