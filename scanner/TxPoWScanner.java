import java.io.BufferedReader;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.minima.objects.TxPoW;
import org.minima.objects.Witness;
import org.minima.objects.base.MiniData;
import org.minima.objects.keys.Signature;
import org.minima.objects.keys.SignatureProof;
import org.minima.database.mmr.MMRProof;
import org.minima.utils.json.JSONArray;
import org.minima.utils.json.JSONObject;
import org.minima.utils.json.parser.JSONParser;

/**
 * TxPoWScanner — reads a `txpow` table to access FULL TxPoW objects with
 * their bodies and witnesses intact. Extracts every on-chain signature,
 * recovers the exact leaf index, and reports per-public-key usage.
 *
 * Supports two backends:
 *   MySQL   — the `txpow` table populated by Minima's MySQL auto-backup.
 *   H2      — the local `txpow.mv.db` from Minima's txpowsql/ directory.
 *
 * Usage:
 *   javac --release 11 -cp /path/to/minima.jar scanner/TxPoWScanner.java
 *
 *   # MySQL backend:
 *   java -cp /path/to/minima.jar:scanner TxPoWScanner \
 *     --host 127.0.0.1:3306 --db archivedb --user u --pass p
 *
 *   # H2 backend (local txpow.mv.db copy):
 *   java -cp /path/to/minima.jar:scanner TxPoWScanner \
 *     --h2 /path/to/txpow_copy.mv.db
 *
 *   # Filter to specific keys (audit mode):
 *   java -cp /path/to/minima.jar:scanner TxPoWScanner \
 *     --h2 /path/to/txpow_copy.mv.db \
 *     --keys keysActionList.json
 *
 *   # Scan a range by internal row ID:
 *   java -cp /path/to/minima.jar:scanner TxPoWScanner \
 *     --h2 /path/to/txpow_copy.mv.db \
 *     --fromid 1 --toid 100000
 */
public class TxPoWScanner {

    // Key geometry is read from each signature (see recoverLeafIndex): classic 64/3
    // (prooflen 6) or block-as-keyuses 128/4 (prooflen 7, minimaCore -blockaskeyuses).
    static final int PAGE_SIZE = 1000;

    static class Usage {
        long usecount = 0;
        long maxleafindex = -1;
        long firstblock = Long.MAX_VALUE;
        long lastblock = -1;
        long localuses = -1;
    }

    static class AnomalyException extends Exception {
        AnomalyException(String m) { super(m); }
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        String h2path = a.get("h2");
        String host = a.get("host");
        String db   = a.getOrDefault("db", "archivedb");
        String user = a.get("user");
        String pass = a.get("pass");
        String keysFile = a.get("keys");
        long fromId = Long.parseLong(a.getOrDefault("fromid", "0"));
        long toId   = Long.parseLong(a.getOrDefault("toid", "-1"));

        if (h2path == null && (host == null || user == null || pass == null)) {
            System.err.println("usage: TxPoWScanner --h2 /path/to/txpow.mv.db"
                    + " [--keys keysActionList.json] [--fromid N] [--toid M]");
            System.err.println("   or: TxPoWScanner --host H:3306 --db archivedb --user U --pass P"
                    + " [--keys keysActionList.json] [--fromid N] [--toid M]");
            System.exit(2);
        }

        Set<String> targets = null;
        Map<String, Long> localUses = new HashMap<>();
        if (keysFile != null) {
            targets = new HashSet<>();
            loadKeysFile(keysFile, targets, localUses);
            System.err.println("Filtering to " + targets.size() + " target keys from " + keysFile);
        }

        Map<String, Usage> result = new TreeMap<>();
        if (targets != null) {
            for (String pk : targets) {
                Usage u = new Usage();
                Long lu = localUses.get(pk);
                if (lu != null) u.localuses = lu;
                result.put(pk, u);
            }
        }

        Connection conn;
        if (h2path != null) {
            Class.forName("org.h2.Driver");
            String path = h2path.replaceAll("\\.mv\\.db$", "");
            String jdbcUrl = "jdbc:h2:" + path + ";MODE=MySQL";
            conn = DriverManager.getConnection(jdbcUrl, "SA", "");
        } else {
            Class.forName("com.mysql.cj.jdbc.Driver");
            String jdbcUrl = "jdbc:mysql://" + host + "/" + db + "?autoReconnect=true";
            conn = DriverManager.getConnection(jdbcUrl, user, pass);
        }

        String countSql = "SELECT COUNT(*) FROM txpow"
                + (toId >= 0 ? " WHERE id BETWEEN ? AND ?" : fromId > 0 ? " WHERE id >= ?" : "");
        PreparedStatement countSt = conn.prepareStatement(countSql);
        if (toId >= 0) { countSt.setLong(1, fromId > 0 ? fromId : 1); countSt.setLong(2, toId); }
        else if (fromId > 0) countSt.setLong(1, fromId);
        ResultSet cr = countSt.executeQuery();
        cr.next();
        long total = cr.getLong(1);
        cr.close(); countSt.close();
        System.err.println("txpow table: " + total + " rows");

        String sql = "SELECT id, txpowid, txpowdata FROM txpow"
                + (toId >= 0 ? " WHERE id BETWEEN ? AND ?" : fromId > 0 ? " WHERE id >= ?" : "")
                + " ORDER BY id ASC LIMIT ? OFFSET ?";
        PreparedStatement ps = conn.prepareStatement(sql);

        long processed = 0, withBody = 0, sigsFound = 0, anomalies = 0;
        long offset = 0;

        while (offset < total) {
            int paramIdx = 1;
            if (toId >= 0) {
                ps.setLong(paramIdx++, fromId > 0 ? fromId : 1);
                ps.setLong(paramIdx++, toId);
            } else if (fromId > 0) {
                ps.setLong(paramIdx++, fromId);
            }
            ps.setInt(paramIdx++, PAGE_SIZE);
            ps.setLong(paramIdx, offset);

            ResultSet rs = ps.executeQuery();
            boolean gotAny = false;
            while (rs.next()) {
                gotAny = true;
                long rowId = rs.getLong("id");
                String txpowid = rs.getString("txpowid");
                byte[] data = rs.getBytes("txpowdata");
                processed++;

                TxPoW txp;
                try {
                    MiniData md = new MiniData(data);
                    txp = TxPoW.convertMiniDataVersion(md);
                } catch (Exception e) {
                    System.err.println("deserialize error id=" + rowId + " txpowid=" + txpowid + ": " + e.getMessage());
                    continue;
                }

                if (txp == null || !txp.hasBody()) continue;
                withBody++;

                long blk = txp.getBlockNumber().getAsLong();

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
                            leaf = -1;
                        }

                        Usage u = result.get(root);
                        if (u == null) { u = new Usage(); result.put(root, u); }
                        u.usecount++;
                        if (leaf >= 0) u.maxleafindex = Math.max(u.maxleafindex, leaf);
                        u.firstblock = Math.min(u.firstblock, blk);
                        u.lastblock = Math.max(u.lastblock, blk);
                        sigsFound++;
                    }
                }
            }
            rs.close();

            if (processed % 10000 == 0 || !gotAny || offset + PAGE_SIZE >= total) {
                System.err.println("... " + processed + "/" + total + " processed, "
                        + withBody + " with body, " + sigsFound + " sigs, " + anomalies + " anomalies");
            }
            if (!gotAny) break;
            offset += PAGE_SIZE;
        }

        ps.close();
        conn.close();

        System.err.println("DONE. processed=" + processed + " withBody=" + withBody
                + " sigsFound=" + sigsFound + " anomalies=" + anomalies);

        JSONArray out = new JSONArray();
        for (Map.Entry<String, Usage> e : result.entrySet()) {
            Usage u = e.getValue();
            JSONObject j = new JSONObject();
            j.put("publickey", e.getKey());
            j.put("usecount", u.usecount);
            j.put("maxleafindex", u.maxleafindex);
            j.put("firstblock", u.usecount == 0 ? -1 : u.firstblock);
            j.put("lastblock", u.lastblock);
            if (u.localuses >= 0) {
                j.put("localuses", u.localuses);
                j.put("reuserisk", u.maxleafindex >= u.localuses);
            }
            out.add(j);
        }
        System.out.println(out.toString());

        boolean anyLocal = result.values().stream().anyMatch(u -> u.localuses >= 0);
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
                        + e.getKey() + "  onchain(max+1)=" + derived
                        + "  localuses=" + u.localuses + "  count=" + u.usecount);
            }
            System.err.println("passes=" + passes + " mismatch=" + fails);
        }
    }

    static long recoverLeafIndex(Signature sig) throws AnomalyException {
        ArrayList<SignatureProof> proofs = sig.getAllSignatureProofs();
        int levels = proofs.size();
        if (levels != 3 && levels != 4) {
            throw new AnomalyException("proofs.size()=" + levels + " (expected 3 or 4)");
        }
        int expectPlen = (levels == 3) ? 6 : 7;
        int kpl = 1 << expectPlen;
        long idx = 0;
        for (SignatureProof sp : proofs) {
            MMRProof proof = sp.getProof();
            int plen = proof.getProofLength();
            if (plen != expectPlen) {
                throw new AnomalyException("level prooflen=" + plen + " (expected " + expectPlen
                        + " for a " + levels + "-level key)");
            }
            int pos = 0;
            for (int i = 0; i < plen; i++) {
                if (proof.getProofChunk(i).isLeft()) {
                    pos |= (1 << i);
                }
            }
            idx = idx * kpl + pos;
        }
        return idx;
    }

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
            if (resp instanceof JSONObject && ((JSONObject) resp).get("keys") instanceof JSONArray)
                keys = (JSONArray) ((JSONObject) resp).get("keys");
            else if (obj.get("keys") instanceof JSONArray)
                keys = (JSONArray) obj.get("keys");
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
