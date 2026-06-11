import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.minima.objects.TxBlock;
import org.minima.objects.TxPoW;
import org.minima.objects.Witness;
import org.minima.objects.base.MiniNumber;
import org.minima.objects.keys.Signature;
import org.minima.objects.keys.SignatureProof;
import org.minima.database.mmr.MMRProof;
import org.minima.utils.mysql.MySQLConnect;
import org.minima.utils.json.JSONArray;
import org.minima.utils.json.JSONObject;
import org.minima.utils.json.parser.JSONParser;

/**
 * KeyUseScanner — witness-exact Minima archive key-use auditor.
 *
 * Iterates every block in a Minima archive (archivedb MySQL), reads every
 * signature in both the main and burn witnesses, matches each signature's
 * ROOT public key, and recovers the exact on-chain leaf index (the mUses value
 * at signing time) from the signature proof's left/right path bits.
 *
 * Output per public key: { publickey, usecount, maxleafindex, firstblock, lastblock }.
 *
 * maxleafindex+1 == the node's true high-water "uses". Compare against a node's
 * local `keys action:list` uses to detect signature-reuse risk after a low resync.
 *
 * Reuses Minima's own classes (via minima.jar) — no manual block parsing.
 */
public class KeyUseScanner {

    // Default key geometry: 64-ary, 3 levels => each level is a 64-leaf MMR (proof length 6).
    static final int KEYS_PER_LEVEL = 64;
    static final int LEVEL_PROOF_LEN = 6; // log2(64)

    static class Usage {
        long usecount = 0;
        long maxleafindex = -1;
        long firstblock = Long.MAX_VALUE;
        long lastblock = -1;
        long localuses = -1; // optional, from keys action:list
        // (block, leafindex) events — only populated in --consistency mode.
        ArrayList<long[]> events = new ArrayList<>();
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);

        String host = a.get("host");
        String db   = a.getOrDefault("db", "archivedb");
        String user = a.get("user");
        String pass = a.get("pass");
        String keysFile = a.get("keys");
        long fromBlock = Long.parseLong(a.getOrDefault("fromblock", "0"));
        long toBlock   = Long.parseLong(a.getOrDefault("toblock", "-1")); // -1 = to tip
        boolean consistency = a.containsKey("consistency");

        if (host == null || user == null || pass == null) {
            System.err.println("usage: KeyUseScanner --host H:3306 --db archivedb --user U --pass P "
                    + "[--keys keysActionList.json] [--fromblock N] [--toblock M]");
            System.exit(2);
        }

        // Target key set (null = index ALL keys encountered).
        Set<String> targets = null;
        Map<String, Long> localUses = new HashMap<>();
        if (keysFile != null) {
            targets = new HashSet<>();
            loadKeysFile(keysFile, targets, localUses);
            System.err.println("Filtering to " + targets.size() + " target keys from " + keysFile);
        }

        Map<String, Usage> result = new TreeMap<>();
        // Pre-seed targets so zero-use keys still appear in output.
        if (targets != null) {
            for (String pk : targets) {
                Usage u = new Usage();
                Long lu = localUses.get(pk);
                if (lu != null) u.localuses = lu;
                result.put(pk, u);
            }
        }

        // Fat jar doesn't ship the JDBC service file, so register the driver explicitly.
        Class.forName("com.mysql.cj.jdbc.Driver");

        MySQLConnect mysql = new MySQLConnect(host, db, user, pass, true /*readonly*/);
        mysql.init();

        long start = fromBlock;
        long lastSeen = -1;
        long blocksProcessed = 0;
        long sigsMatched = 0;
        long anomalies = 0;

        while (true) {
            ArrayList<TxBlock> blocks = mysql.loadBlockRange(new MiniNumber(start));
            if (blocks.isEmpty()) break;

            long batchMax = start;
            for (TxBlock tb : blocks) {
                TxPoW txp = tb.getTxPoW();
                long blk = txp.getBlockNumber().getAsLong();
                batchMax = Math.max(batchMax, blk);
                if (toBlock >= 0 && blk > toBlock) { batchMax = blk; continue; }

                for (Witness w : new Witness[]{ txp.getWitness(), txp.getBurnWitness() }) {
                    if (w == null) continue;
                    for (Signature sig : w.getAllSignatures()) {
                        String root = sig.getRootPublicKey().to0xString().toUpperCase();
                        if (targets != null && !targets.contains(root)) continue;

                        long leaf;
                        try {
                            leaf = recoverLeafIndex(sig);
                        } catch (AnomalyException ae) {
                            anomalies++;
                            if (anomalies <= 20) {
                                System.err.println("ANOMALY blk " + blk + " key " + root + " : " + ae.getMessage());
                            }
                            // Fallback: count-only contribution, no index.
                            leaf = -1;
                        }

                        Usage u = result.get(root);
                        if (u == null) { u = new Usage(); result.put(root, u); }
                        u.usecount += 1;
                        if (leaf >= 0) u.maxleafindex = Math.max(u.maxleafindex, leaf);
                        u.firstblock = Math.min(u.firstblock, blk);
                        u.lastblock = Math.max(u.lastblock, blk);
                        if (consistency && leaf >= 0) u.events.add(new long[]{blk, leaf});
                        sigsMatched++;
                    }
                }
            }

            blocksProcessed += blocks.size();
            lastSeen = batchMax;
            if (blocksProcessed % 25000 < blocks.size()) {
                System.err.println("... block " + lastSeen + "  (" + blocksProcessed + " scanned, "
                        + sigsMatched + " sigs matched)");
            }

            long next = batchMax + 1;
            if (next <= start) break; // safety: no progress
            start = next;
            if (toBlock >= 0 && start > toBlock) break;
        }

        System.err.println("DONE. blocks=" + blocksProcessed + " tip=" + lastSeen
                + " sigsMatched=" + sigsMatched + " anomalies=" + anomalies);

        if (consistency) {
            consistencyReport(result);
        }

        // Emit JSON
        JSONArray out = new JSONArray();
        boolean anyLocal = false;
        for (Map.Entry<String, Usage> e : result.entrySet()) {
            Usage u = e.getValue();
            JSONObject j = new JSONObject();
            j.put("publickey", e.getKey());
            j.put("usecount", u.usecount);
            j.put("maxleafindex", u.maxleafindex);
            j.put("firstblock", u.usecount == 0 ? -1 : u.firstblock);
            j.put("lastblock", u.lastblock);
            if (u.localuses >= 0) {
                anyLocal = true;
                j.put("localuses", u.localuses);
                // reuserisk: node will next issue leaf == localuses; risk if an on-chain
                // use is at or beyond that index.
                j.put("reuserisk", u.maxleafindex >= u.localuses);
            }
            out.add(j);
        }
        System.out.println(out.toString());

        // Validation summary to stderr if local uses were supplied.
        if (anyLocal) {
            System.err.println("\n=== VALIDATION (maxleafindex+1 vs localuses) ===");
            int passes = 0, fails = 0;
            for (Map.Entry<String, Usage> e : result.entrySet()) {
                Usage u = e.getValue();
                if (u.localuses < 0) continue;
                long derived = u.maxleafindex + 1;
                boolean ok = derived == u.localuses;
                if (ok) passes++; else fails++;
                System.err.println((ok ? "OK  " : "MISMATCH ")
                        + e.getKey().substring(0, 18) + "...  onchain(max+1)=" + derived
                        + "  localuses=" + u.localuses + "  count=" + u.usecount);
            }
            System.err.println("passes=" + passes + " mismatch=" + fails);
        }
    }

    static class AnomalyException extends Exception {
        AnomalyException(String m) { super(m); }
    }

    /**
     * Archive reuse scan. (The decoder itself is proven exact by CalibrateDecoder.)
     *
     * On-chain signatures are the security-relevant set: a Winternitz leaf is only
     * forgeable once its signature is PUBLICLY REVEALED, i.e. on-chain. Signing is
     * sequential, so a healthy key's revealed leaf indices are strictly increasing in
     * block order. Gaps are benign (the node signs more than it broadcasts, and a resync
     * with keyuses set HIGH skips leaves). But a NON-MONOTONIC sequence — a lower leaf
     * revealed in a LATER block than a higher one — means the key's counter went BACKWARDS:
     * a resync with keyuses set too LOW, re-revealing already-spent leaves. That is real
     * on-chain reuse exposure.
     */
    static void consistencyReport(Map<String, Usage> result) {
        System.err.println("\n=== ARCHIVE REUSE SCAN (on-chain revealed leaves) ===");
        int healthy = 0, gapped = 0, exposed = 0, considered = 0;
        // Look at the busiest keys first.
        java.util.List<Map.Entry<String, Usage>> ents = new java.util.ArrayList<>(result.entrySet());
        ents.sort((x, y) -> Long.compare(y.getValue().usecount, x.getValue().usecount));

        int shown = 0;
        for (Map.Entry<String, Usage> e : ents) {
            Usage u = e.getValue();
            if (u.usecount < 2) continue;
            considered++;

            // sort events by (block, leaf)
            java.util.List<long[]> ev = new java.util.ArrayList<>(u.events);
            ev.sort((p, q) -> p[0] != q[0] ? Long.compare(p[0], q[0]) : Long.compare(p[1], q[1]));

            Set<Long> leaves = new HashSet<>();
            boolean monotonic = true;
            long prev = -1, min = Long.MAX_VALUE, max = -1;
            for (long[] x : ev) {
                long leaf = x[1];
                if (leaf <= prev) monotonic = false; // strictly increasing in block order
                prev = leaf;
                leaves.add(leaf);
                min = Math.min(min, leaf);
                max = Math.max(max, leaf);
            }
            boolean distinct = leaves.size() == ev.size();

            // monotonic increasing in block order = healthy. duplicates or a backwards
            // step = a leaf re-revealed = on-chain reuse exposure.
            String klass;
            if (monotonic && distinct && min == 0) { klass = "HEALTHY"; healthy++; }
            else if (monotonic && distinct)        { klass = "HEALTHY-OFFSET"; gapped++; }
            else                                    { klass = "REUSE-EXPOSURE"; exposed++; }

            if (shown < 15 || klass.equals("REUSE-EXPOSURE")) {
                System.err.println(String.format("%-15s %s  n=%d  min=%d max=%d  monotonic=%s distinct=%s",
                        klass, e.getKey().substring(0, 18) + "...", ev.size(), min, max, monotonic, distinct));
                shown++;
            }
        }
        System.err.println("considered(keys>=2 sigs)=" + considered
                + "  HEALTHY=" + healthy + "  HEALTHY-OFFSET=" + gapped + "  REUSE-EXPOSURE=" + exposed);
        System.err.println(exposed > 0
            ? "NOTE: " + exposed + " key(s) show non-monotonic on-chain leaf order = real reuse exposure"
              + " (resynced with keyuses too low). Decoder correctness is proven separately by CalibrateDecoder."
            : "NOTE: no on-chain reuse exposure among multi-sig keys.");
    }

    /**
     * Recover the leaf index (== mUses at signing time) from a Signature.
     *
     * baseConversion(mUses, 64, 3) = [pos0, pos1, pos2] (most-significant first),
     * and TreeKey.sign adds the SignatureProofs in that same order. Each level's
     * MMRProof encodes its position via the chunk left/right flags: in
     * MMRProof.calculateProof, a chunk.isLeft()==true means the sibling is the LEFT
     * child, i.e. the signed node is the RIGHT child -> position bit set. Chunk 0 is
     * the leaf-level sibling = LSB.
     *
     *   pos_L   = sum_i ( chunk[i].isLeft() ? 1<<i : 0 )      over the 6 chunks
     *   leaf    = pos0*64*64 + pos1*64 + pos2
     */
    static long recoverLeafIndex(Signature sig) throws AnomalyException {
        ArrayList<SignatureProof> proofs = sig.getAllSignatureProofs();
        if (proofs.size() != 3) {
            throw new AnomalyException("proofs.size()=" + proofs.size() + " (expected 3)");
        }
        long idx = 0;
        for (SignatureProof sp : proofs) {
            MMRProof proof = sp.getProof();
            int plen = proof.getProofLength();
            if (plen != LEVEL_PROOF_LEN) {
                throw new AnomalyException("level prooflen=" + plen + " (expected " + LEVEL_PROOF_LEN + ")");
            }
            int pos = 0;
            for (int i = 0; i < plen; i++) {
                if (proof.getProofChunk(i).isLeft()) {
                    pos |= (1 << i);
                }
            }
            idx = idx * KEYS_PER_LEVEL + pos;
        }
        return idx;
    }

    // --- helpers ---

    static void loadKeysFile(String path, Set<String> targets, Map<String, Long> localUses) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        Object parsed = new JSONParser().parse(sb.toString());

        JSONArray keys = null;
        if (parsed instanceof JSONObject) {
            JSONObject obj = (JSONObject) parsed;
            Object resp = obj.get("response");
            if (resp instanceof JSONObject && ((JSONObject) resp).get("keys") instanceof JSONArray) {
                keys = (JSONArray) ((JSONObject) resp).get("keys");
            } else if (obj.get("keys") instanceof JSONArray) {
                keys = (JSONArray) obj.get("keys");
            }
        } else if (parsed instanceof JSONArray) {
            keys = (JSONArray) parsed;
        }
        if (keys == null) throw new IllegalArgumentException("could not find keys[] in " + path);

        for (Object o : keys) {
            if (o instanceof JSONObject) {
                JSONObject k = (JSONObject) o;
                String pk = String.valueOf(k.get("publickey")).toUpperCase();
                targets.add(pk);
                Object uses = k.get("uses");
                if (uses != null) localUses.put(pk, Long.parseLong(String.valueOf(uses)));
            } else {
                targets.add(String.valueOf(o).toUpperCase());
            }
        }
    }

    static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                String key = args[i].substring(2);
                String val = (i + 1 < args.length && !args[i + 1].startsWith("--")) ? args[++i] : "true";
                m.put(key, val);
            }
        }
        return m;
    }
}
