import java.io.BufferedReader;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.minima.objects.Address;
import org.minima.utils.json.JSONArray;
import org.minima.utils.json.JSONObject;
import org.minima.utils.json.parser.JSONParser;

/**
 * KeyUses — coin-based key-reuse audit.
 *
 * For each of a node's keys (from `keys action:list`), derive its default address
 * exactly as Minima does — new Address("RETURN SIGNEDBY(<publickey>)") — then query
 * the archive `coins` table for how many times that address was spent FROM.
 *
 * IMPORTANT (the spent-coins-vs-signatures distinction):
 *   - spent_coins  = number of UTXOs spent at the address  (UPPER BOUND on uses)
 *   - signatures   = COUNT(DISTINCT blockspent)            (~ actual key uses)
 * One signature can spend many coins in a single transaction, so spent_coins
 * over-counts. The node's `uses` counter increments once per signature, so we
 * compare it against `signatures`, never against spent_coins.
 *
 * reuse risk  ⇔  on-chain signatures  >  node's local `uses` counter
 * (the chain proves the key signed more often than the node thinks → it was
 *  resynced with keyuses too low and has reused / will reuse a revealed leaf).
 *
 * Caveats surfaced honestly:
 *   - signatures uses distinct spend-blocks as the per-transaction proxy; two
 *     separate txns from one key in the same block would merge (rare under-count).
 *   - only the key's DEFAULT address is checked; uses via custom-script/multisig
 *     addresses controlled by the same key are not counted here.
 */
public class KeyAudit {

    static final long MAXUSES = 262144;
    static final long MARGIN  = 256;

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        String host = a.get("host"), db = a.getOrDefault("db", "archivedb");
        String user = a.get("user"), pass = a.get("pass"), keysFile = a.get("keys");
        if (host == null || user == null || pass == null || keysFile == null) {
            System.err.println("usage: KeyAudit --host H:3306 --db archivedb --user U --pass P --keys keysActionList.json");
            System.exit(2);
        }

        // Parse keys action:list
        ArrayList<JSONObject> keys = loadKeys(keysFile);

        Class.forName("com.mysql.cj.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://" + host + "/" + db + "?autoReconnect=true", user, pass);
        PreparedStatement ps = con.prepareStatement(
            "SELECT COUNT(*) AS spent_coins, COUNT(DISTINCT blockspent) AS signatures, " +
            "MIN(blockspent) AS firstblk, MAX(blockspent) AS lastblk " +
            "FROM coins WHERE address=? AND spent=1");

        JSONArray out = new JSONArray();
        boolean anyRisk = false;
        long recommended = 0;

        for (JSONObject k : keys) {
            String pk = String.valueOf(k.get("publickey"));
            long localuses = asLong(k.get("uses"), -1);

            // Derive the default address exactly as Minima's Wallet does.
            String script = "RETURN SIGNEDBY(" + pk + ")";
            String address = new Address(script).getAddressData().to0xString();

            ps.setString(1, address);
            long spentCoins = 0, signatures = 0, firstBlk = -1, lastBlk = -1;
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    spentCoins = rs.getLong("spent_coins");
                    signatures = rs.getLong("signatures");
                    firstBlk   = rs.getLong("firstblk");
                    lastBlk    = rs.getLong("lastblk");
                    if (rs.wasNull()) lastBlk = -1;
                }
            }

            boolean risk = localuses >= 0 && signatures > localuses;
            if (risk) anyRisk = true;
            recommended = Math.max(recommended, Math.max(signatures, Math.max(localuses, 0)));

            JSONObject j = new JSONObject();
            j.put("publickey", pk);
            j.put("address", address);
            j.put("localuses", localuses);
            j.put("onchain_signatures", signatures);
            j.put("spent_coins_upperbound", spentCoins);
            j.put("firstblock", spentCoins == 0 ? -1 : firstBlk);
            j.put("lastblock", lastBlk);
            j.put("reuserisk", risk);
            out.add(j);
        }
        ps.close();
        con.close();

        System.out.println(out.toString());

        // human summary on stderr
        System.err.println("\n=== KEY AUDIT (coin-based) ===");
        System.err.println("key                  local_uses  onchain_sigs  spent_coins  risk");
        for (Object o : out) {
            JSONObject j = (JSONObject) o;
            System.err.println(String.format("%s  %10s  %12s  %11s  %s",
                String.valueOf(j.get("publickey")).substring(0, 18) + "...",
                j.get("localuses"), j.get("onchain_signatures"),
                j.get("spent_coins_upperbound"), ((Boolean) j.get("reuserisk")) ? "*** REUSE ***" : "ok"));
        }
        System.err.println(anyRisk
            ? "\nAT RISK: on-chain signatures exceed the node's counter on >=1 key. Recommended keyuses on next resync: " + (recommended + MARGIN)
            : "\nNo reuse detected. Recommended keyuses floor for any future resync: " + (recommended + MARGIN));
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
        } else if (parsed instanceof JSONArray) {
            arr = (JSONArray) parsed;
        }
        if (arr == null) throw new IllegalArgumentException("could not find keys[] in " + path);
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
