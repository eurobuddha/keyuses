# KeyUses — Minima key-reuse risk auditor

Minima signatures are **stateful**. Each of a node's 64 keys is a 64-ary, 3-level
hash-based (Winternitz) tree capped at **262,144** one-time signatures. Every signature
consumes the next leaf; the node tracks this with a per-key `uses` counter. **Reusing a
leaf is forgeable** (a Winternitz OTS reused twice leaks the private key).

The operational danger: when you **re-sync from your seed**, the regenerated keys start at
`uses = 0` and the node can't know how many times they were really used. You must pass
`keyuses:N` on `archive action:import/resync`. **Set it too low and the node re-issues
leaves it already spent on-chain.** KeyUses detects exactly this.

## Data model (important)

Minima keeps coin history in layers, and getting this right is the whole game:

- **Cascade** — the live, *unpruned* tip: roughly the **last 24h** of full blocks every node holds.
- **Archive (`syncblock`)** — everything **older**, archived back to block 1 (archive nodes only).
- **`coins` table** — a flattened convenience view in `archivedb`; on our node it had **stalled**
  ~100k blocks back, so it is NOT used.
- **MMR** — the cryptographic accumulator; coins get pruned into it with no per-coin detail.

So complete spend history = **`syncblock` (block 1 → ~24h ago) + cascade (last ~24h)**.

Critically, the archive does **not** retain transaction *witnesses* — `TxBlock` keeps the block's
spent/created coins but discards the signatures. So witness-exact leaf-index recovery over history
is impossible; we measure key uses from **coin spends** instead.

## How it works

1. **Coin scanner** (`scanner/CoinScanner.java`) — reuses Minima's classes to iterate `syncblock`,
   read each block's spent coins (`TxBlock.mSpentCoins`), and tally per address:
   - `spent_coins` — UTXOs spent at the address (an **upper bound** on uses),
   - `spend_blocks` — distinct blocks spent in (**≈ key uses / signatures**).
   One signature can spend many coins in one transaction, so `spent_coins` over-counts;
   `spend_blocks` collapses a multi-coin transaction to one. The node's `uses` counter increments
   once per signature, so we compare it against **`spend_blocks`, never `spent_coins`.**

2. **Per-key audit** — each key's default address is derived exactly as Minima does,
   `new Address("RETURN SIGNEDBY(<publickey>)")`, then looked up in the spend index.
   **reuse suspected ⇔ on-chain `spend_blocks` > node's local `uses`** (the chain proves the key
   signed more often than the node thinks → resynced with `keyuses` too low). Validated against a
   live node: 63/64 keys matched `uses` exactly or off-by-one (the off-by-ones being the cascade
   gap — the most recent spend not yet archived), and never *above* `uses`.

3. **Cascade top-up** — the last ~24h (cascade) is read from the live node so very recent reuse
   isn't missed.

4. **Backend** + **MiniDapp** — the dapp reads `keys action:list` locally and the node's addresses,
   looks each up in the (archive + cascade) spend index, sums per key, compares to `uses`, and
   prints the safe `keyuses` to set on the next resync.

### Witness path (recent history only)
`scanner/KeyUseScanner.java` + `scanner/CalibrateDecoder.java` implement *witness-exact* leaf-index
recovery — proven correct for every index `0..262143`. It's unusable over the archive (no retained
witnesses) but works on the unpruned tip / the explorer's post-block-~1.15M txpows, where exact
leaf indices are available. Kept for that optional precision path.

## Build & run the coin scanner

```bash
# compile against the node jar (target Java 11 for the server's JRE)
javac --release 11 -cp /path/to/minima.jar scanner/CoinScanner.java

# build the full address -> spend index (read-only DB user is enough)
java -cp /path/to/minima.jar:scanner CoinScanner \
  --host 127.0.0.1:3306 --db archivedb --user <ro_user> --pass <pw> > coin_index.json

# or audit one node's keys directly (derives default addresses, prints reuse verdict)
java -cp /path/to/minima.jar:scanner CoinScanner \
  --host 127.0.0.1:3306 --db archivedb --user <ro_user> --pass <pw> --keys keysActionList.json
```

The fat jar bundles the MySQL driver but not its JDBC service file, so the scanners register
`com.mysql.cj.jdbc.Driver` explicitly.

## Backend (`backend/KeyUsesServer.java`)

A small JDK-`HttpServer` service. Loads the spend index (TSV) into memory, and for each posted
public key derives its default address and returns spend stats:

```
GET /keyaudit?keys=0xPK1,0xPK2,...
  -> { status, archive_tip, keys:[ {publickey,address,spend_blocks,spent_coins,firstblock,lastblock} ] }
GET /keyaudit/health
```

Deployed on eurobuddha behind `pm2` (`keyuses-backend`, localhost:3010) and an Apache reverse
proxy at `https://eurobuddha.com/keyaudit`. Serves **only public spend data** — no wallet data,
no DB writes. Coverage is the archive (`archive_tip`); the last ~24h (cascade) is disclosed in the
dapp and topped up separately.

Build: `javac --release 11 -cp /path/to/minima.jar backend/KeyUsesServer.java`.

## Notes / gotchas discovered

- `MySQLConnect.loadFirstBlock()` / `loadLastBlock()` are **mislabeled** in Minima (their SQL is
  `DESC`/`ASC` respectively). The scanner ignores the names and paginates `loadBlockRange` from the
  earliest block until empty.
- The Minima mainnet chain is very sparse (≈hundreds of signed transactions across millions of
  blocks), so the on-chain key-usage index is small.
