import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.minima.objects.Address;
import org.minima.objects.Coin;
import org.minima.objects.CoinProof;
import org.minima.objects.TxBlock;
import org.minima.objects.base.MiniNumber;
import org.minima.utils.mysql.MySQLConnect;
import org.minima.utils.json.JSONArray;
import org.minima.utils.json.JSONObject;
import org.minima.utils.json.parser.JSONParser;

/**
 * KeyUses coin-based spend index, built from the archive `syncblock` (NOT the stalled
 * flat `coins` table). Each TxBlock carries that block's spent coins (mSpentCoins);
 * we tally, per address:
 *   - spent_coins   = number of UTXOs spent at the address  (UPPER BOUND on uses)
 *   - spend_blocks  = number of distinct blocks it was spent in (~ key uses / signatures)
 * One signature can spend many coins in one transaction, so spent_coins over-counts;
 * spend_blocks collapses a multi-coin transaction to one. Compare spend_blocks (not
 * spent_coins) against a node's per-signature `uses` counter.
 *
 * Modes:
 *   --keys keysActionList.json : derive each key's default address (RETURN SIGNEDBY(pk)),
 *                                filter to those, emit a per-KEY audit (with reuserisk).
 *   (no --keys)                : index ALL addresses → emit address -> spend stats.
 *
 * Coverage: syncblock = block 1 .. ~24h ago. The last ~24h (cascade / live tip) must be
 * added separately from the live node; this tool reports its max block so the caller knows
 * the cut-off.
 */
public class CoinScanner {

    static final long MARGIN = 256;

    static class Stat {
        long spentCoins = 0;
        long spendBlocks = 0;
        long lastBlockCounted = -1; // for distinct-block counting
        long firstBlock = Long.MAX_VALUE;
        long lastBlock = -1;
        long localuses = -1; // audit mode
        String pubkey = null; // audit mode
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        String host = a.get("host"), db = a.getOrDefault("db", "archivedb");
        String user = a.get("user"), pass = a.get("pass"), keysFile = a.get("keys");
        boolean tsv = a.containsKey("tsv"); // index mode: emit TSV instead of JSON
        long fromBlock = Long.parseLong(a.getOrDefault("fromblock", "0"));
        if (host == null || user == null || pass == null) {
            System.err.println("usage: CoinScanner --host H:3306 --db archivedb --user U --pass P [--keys keys.json] [--fromblock N]");
            System.exit(2);
        }

        // audit mode: derive target addresses from keys
        Set<String> targets = null;
        Map<String, Stat> result = new TreeMap<>();
        if (keysFile != null) {
            targets = new HashSet<>();
            for (JSONObject k : loadKeys(keysFile)) {
                String pk = String.valueOf(k.get("publickey"));
                String addr = new Address("RETURN SIGNEDBY(" + pk + ")").getAddressData().to0xString().toUpperCase();
                Stat s = new Stat();
                s.pubkey = pk;
                s.localuses = asLong(k.get("uses"), -1);
                result.put(addr, s);
                targets.add(addr);
            }
            System.err.println("audit mode: " + targets.size() + " default addresses derived");
        }

        Class.forName("com.mysql.cj.jdbc.Driver");
        MySQLConnect mysql = new MySQLConnect(host, db, user, pass, true);
        mysql.init();

        long start = fromBlock, lastSeen = -1, blocks = 0, spends = 0;
        while (true) {
            ArrayList<TxBlock> batch = mysql.loadBlockRange(new MiniNumber(start));
            if (batch.isEmpty()) break;
            long batchMax = start;
            for (TxBlock tb : batch) {
                long blk = tb.getTxPoW().getBlockNumber().getAsLong();
                batchMax = Math.max(batchMax, blk);
                for (CoinProof cp : tb.getInputCoinProofs()) {
                    Coin coin = cp.getCoin();
                    String addr = coin.getAddress().to0xString().toUpperCase();
                    if (targets != null && !targets.contains(addr)) continue;
                    Stat s = result.get(addr);
                    if (s == null) { s = new Stat(); result.put(addr, s); }
                    s.spentCoins++;
                    if (blk != s.lastBlockCounted) { s.spendBlocks++; s.lastBlockCounted = blk; }
                    s.firstBlock = Math.min(s.firstBlock, blk);
                    s.lastBlock = Math.max(s.lastBlock, blk);
                    spends++;
                }
            }
            blocks += batch.size();
            lastSeen = batchMax;
            if (blocks % 100000 < batch.size()) {
                System.err.println("... block " + lastSeen + " (" + blocks + " scanned, " + spends + " spends, " + result.size() + " addrs)");
            }
            long next = batchMax + 1;
            if (next <= start) break;
            start = next;
        }
        System.err.println("DONE. blocks=" + blocks + " archiveTip=" + lastSeen + " spends=" + spends + " addrs=" + result.size());
        System.err.println("NOTE: coverage = block 1 .. " + lastSeen + " (archive). The last ~24h (cascade) is NOT in here.");

        // Fast TSV index output (no JSON), for the backend to load directly.
        if (tsv && targets == null) {
            StringBuilder sb = new StringBuilder(result.size() * 96);
            for (Map.Entry<String, Stat> e : result.entrySet()) {
                Stat s = e.getValue();
                sb.append(e.getKey()).append('\t').append(s.spendBlocks).append('\t')
                  .append(s.spentCoins).append('\t')
                  .append(s.spentCoins == 0 ? -1 : s.firstBlock).append('\t')
                  .append(s.lastBlock).append('\n');
            }
            System.out.print(sb);
            return;
        }

        JSONArray out = new JSONArray();
        boolean anyRisk = false;
        long recommend = 0;
        for (Map.Entry<String, Stat> e : result.entrySet()) {
            Stat s = e.getValue();
            JSONObject j = new JSONObject();
            if (s.pubkey != null) { // audit mode
                j.put("publickey", s.pubkey);
                j.put("address", e.getKey());
                j.put("localuses", s.localuses);
                j.put("onchain_signatures", s.spendBlocks);
                j.put("spent_coins_upperbound", s.spentCoins);
                boolean risk = s.localuses >= 0 && s.spendBlocks > s.localuses;
                if (risk) anyRisk = true;
                recommend = Math.max(recommend, Math.max(s.spendBlocks, Math.max(s.localuses, 0)));
                j.put("reuserisk", risk);
            } else { // index mode
                j.put("address", e.getKey());
                j.put("spend_blocks", s.spendBlocks);
                j.put("spent_coins", s.spentCoins);
            }
            j.put("firstblock", s.spentCoins == 0 ? -1 : s.firstBlock);
            j.put("lastblock", s.lastBlock);
            out.add(j);
        }
        System.out.println(out.toString());

        if (targets != null) {
            System.err.println("\n=== KEY AUDIT (coin-based, archive only) ===");
            System.err.println("pubkey               local  onchain_sigs  spent_coins  risk");
            for (Object o : out) {
                JSONObject j = (JSONObject) o;
                System.err.println(String.format("%s  %5s  %12s  %11s  %s",
                    String.valueOf(j.get("publickey")).substring(0,18)+"...",
                    j.get("localuses"), j.get("onchain_signatures"), j.get("spent_coins_upperbound"),
                    ((Boolean)j.get("reuserisk")) ? "*** REUSE ***" : "ok"));
            }
            System.err.println(anyRisk
                ? "\nAT RISK on >=1 key. Recommended keyuses on next resync: " + (recommend + MARGIN)
                : "\nNo reuse detected (archive only; add cascade for last 24h). keyuses floor: " + (recommend + MARGIN));
        }
    }

    static ArrayList<JSONObject> loadKeys(String path) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line; while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        Object parsed = new JSONParser().parse(sb.toString());
        JSONArray arr = null;
        if (parsed instanceof JSONObject) {
            Object resp = ((JSONObject) parsed).get("response");
            if (resp instanceof JSONObject && ((JSONObject) resp).get("keys") instanceof JSONArray)
                arr = (JSONArray) ((JSONObject) resp).get("keys");
            else if (((JSONObject) parsed).get("keys") instanceof JSONArray)
                arr = (JSONArray) ((JSONObject) parsed).get("keys");
        } else if (parsed instanceof JSONArray) arr = (JSONArray) parsed;
        if (arr == null) throw new IllegalArgumentException("no keys[] in " + path);
        ArrayList<JSONObject> out = new ArrayList<>();
        for (Object o : arr) out.add((JSONObject) o);
        return out;
    }

    static long asLong(Object o, long def) {
        if (o == null) return def;
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return def; }
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
