# KeyUses — Minima key-reuse risk auditor

Minima signatures are **stateful**. Each of a node's 64 keys is a 64-ary, 3-level
hash-based (Winternitz) tree capped at **262,144** one-time signatures. Every signature
consumes the next leaf; the node tracks this with a per-key `uses` counter. **Reusing a
leaf is forgeable** (a Winternitz OTS reused twice leaks the private key).

The operational danger: when you **re-sync from your seed**, the regenerated keys start at
`uses = 0` and the node can't know how many times they were really used. You must pass
`keyuses:N` on `archive action:import/resync`. **Set it too low and the node re-issues
leaves it already spent on-chain.** KeyUses detects exactly this.

## How it works

1. **Scanner** (`scanner/KeyUseScanner.java`) — reuses Minima's own classes (via `minima.jar`)
   to iterate an archive (`archivedb` MySQL), read every signature in both the main and burn
   witnesses, match each by its root public key, and recover the **exact on-chain leaf index**
   from the signature proof's left/right path bits. Output per key:
   `{publickey, usecount, maxleafindex, firstblock, lastblock}`.
   - The recovered `maxleafindex` is the metric: an over-high prior resync leaves index gaps,
     so a raw `usecount` is only a lower bound.
   - `--consistency` validates the decoder with no wallet access: a never-resynced key's
     on-chain signatures must decode to a contiguous, block-monotonic run `0..N-1`.

2. **Backend** (`backend/server.js`) — loads the scanner's JSON index into memory (the chain is
   sparse, so the set of distinct signing keys is small) and serves fast lookups:
   `GET /keyaudit?keys=0xPK1,0xPK2,...` → per-key usage (zero-filled on miss). Public keys only.

3. **MiniDapp** (`minidapp/`) — installed on the user's node. Reads `keys action:list` locally,
   sends the 64 **public** keys to the backend (or uses a self-hosted archive scan), then flags
   any key where on-chain `maxleafindex >= localuses` (node primed to reuse) and prints the exact
   `keyuses` to set on the next resync.

## Build & run the scanner

```bash
# compile against the node jar (target Java 11 for the server's JRE)
javac --release 11 -cp /path/to/minima.jar scanner/KeyUseScanner.java

# run against an archivedb (read-only DB user is enough)
java -cp /path/to/minima.jar:scanner KeyUseScanner \
  --host 127.0.0.1:3306 --db archivedb --user <ro_user> --pass <pw> \
  [--keys keysActionList.json] [--consistency] [--fromblock N] [--toblock M]
```

The fat jar bundles the MySQL driver but not its JDBC service file, so the scanner registers
`com.mysql.cj.jdbc.Driver` explicitly.

## Notes / gotchas discovered

- `MySQLConnect.loadFirstBlock()` / `loadLastBlock()` are **mislabeled** in Minima (their SQL is
  `DESC`/`ASC` respectively). The scanner ignores the names and paginates `loadBlockRange` from the
  earliest block until empty.
- The Minima mainnet chain is very sparse (≈hundreds of signed transactions across millions of
  blocks), so the on-chain key-usage index is small.
