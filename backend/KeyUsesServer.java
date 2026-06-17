import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.minima.objects.Address;
import org.minima.objects.base.MiniData;
import org.minima.utils.json.JSONArray;
import org.minima.utils.json.JSONObject;

/**
 * KeyUses audit backend (Java).
 *
 * Loads the archive spend index (TSV: address \t spend_blocks \t spent_coins \t first \t last),
 * built by CoinScanner, into memory. Serves:
 *
 *   GET /keyaudit?keys=0xPK1,0xPK2,...
 *     -> derives each key's DEFAULT address — new Address("RETURN SIGNEDBY(<pk>)") — the exact
 *        way Minima does, looks it up, and returns per-key spend stats. Misses are zero-filled.
 *        { status:true, archive_tip:<block>, keys:[ {publickey,address,spend_blocks,spent_coins,firstblock,lastblock} ] }
 *
 *   GET /keyaudit/health  -> { status:true, addresses:N, archive_tip:<block> }
 *
 * `spend_blocks` (distinct blocks the address was spent in) ~ number of times the key signed.
 * The dapp compares that against the node's local `uses`. Only public data is served.
 *
 * Coverage is the archive (block 1 .. ~24h ago). The last ~24h (cascade) is added by the dapp/
 * a separate top-up; archive_tip tells the caller the cut-off.
 */
public class KeyUsesServer {

    static Map<String, long[]> INDEX = new HashMap<>(300000);
    // Known one-time-key REUSE: 0x-address (UPPER) -> { reuse_count, balance }. Public keys/facts only.
    static volatile Map<String, long[]> REUSE = new HashMap<>();
    static volatile String REUSE_FILE = null;
    static volatile long REUSE_MTIME = 0;
    static long ARCHIVE_TIP = -1;
    static final int MAX_KEYS = 256;
    static final java.util.regex.Pattern PUBKEY = java.util.regex.Pattern.compile("^0x[0-9A-Fa-f]{64}$");

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        int port = Integer.parseInt(a.getOrDefault("port", "3010"));
        String indexFile = a.getOrDefault("index", "coin_index.tsv");
        REUSE_FILE = a.get("reuse"); // CSV: miniaddress,signature_count,balance (header allowed)

        loadIndex(indexFile);
        loadReuse();
        // hot-reload the reuse list (the harvester appends to it) once a minute
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(
            KeyUsesServer::loadReuse, 60, 60, java.util.concurrent.TimeUnit.SECONDS);

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/keyaudit", KeyUsesServer::handle);
        server.createContext("/reuse", KeyUsesServer::handleReuse);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4));
        server.start();
        System.err.println("KeyUses backend on 127.0.0.1:" + port + " — " + INDEX.size()
                + " addresses, archive_tip=" + ARCHIVE_TIP + ", reuse=" + REUSE.size());
    }

    // Load the reuse list (Mx,count,balance). Converts Mx->0x. No signatures involved.
    static void loadReuse() {
        if (REUSE_FILE == null) return;
        try {
            java.io.File f = new java.io.File(REUSE_FILE);
            if (!f.exists()) return;
            if (f.lastModified() == REUSE_MTIME) return; // unchanged
            Map<String, long[]> m = new HashMap<>();
            try (java.io.BufferedReader br = Files.newBufferedReader(f.toPath(), StandardCharsets.UTF_8)) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] p = line.split(",");
                    if (p.length < 3) continue;
                    String addr = p[0].trim();
                    if (addr.equalsIgnoreCase("miniaddress") || addr.equalsIgnoreCase("address")) continue; // header
                    String hex;
                    try {
                        if (addr.toLowerCase().startsWith("mx")) hex = Address.convertMinimaAddress(addr).to0xString();
                        else hex = new MiniData(addr).to0xString();
                    } catch (Exception e) { continue; }
                    long count, bal;
                    try { count = Long.parseLong(p[1].trim()); bal = (long) Double.parseDouble(p[2].trim()); }
                    catch (NumberFormatException e) { continue; }
                    m.put(hex.toUpperCase(), new long[]{ count, bal });
                }
            }
            REUSE = m;
            REUSE_MTIME = f.lastModified();
            System.err.println("loaded reuse list: " + m.size() + " reused addresses");
        } catch (Exception e) {
            System.err.println("reuse load failed: " + e.getMessage());
        }
    }

    static void loadIndex(String path) throws IOException {
        long maxLast = -1, explicitTip = -1;
        try (java.io.BufferedReader br = Files.newBufferedReader(Paths.get(path), StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty()) continue;
                if (line.charAt(0) == '#') {
                    // "#TIP\t<block>" header = the real scanned tip
                    if (line.startsWith("#TIP\t")) {
                        try { explicitTip = Long.parseLong(line.substring(5).trim()); } catch (NumberFormatException ignore) {}
                    }
                    continue;
                }
                String[] p = line.split("\t");
                if (p.length < 5) continue;
                long[] v = new long[]{ Long.parseLong(p[1]), Long.parseLong(p[2]), Long.parseLong(p[3]), Long.parseLong(p[4]) };
                INDEX.put(p[0].toUpperCase(), v);
                if (v[3] > maxLast) maxLast = v[3];
            }
        }
        // Prefer the explicit scanned tip; fall back to the highest spend block for older index files.
        ARCHIVE_TIP = explicitTip >= 0 ? explicitTip : maxLast;
        System.err.println("loaded index: " + INDEX.size() + " addresses, archive_tip=" + ARCHIVE_TIP
                + (explicitTip >= 0 ? " (from #TIP)" : " (inferred from max spend block)"));
    }

    static void handle(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Content-Type", "application/json");

        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getRawQuery();

        if (path.endsWith("/health")) {
            send(ex, 200, "{\"status\":true,\"addresses\":" + INDEX.size() + ",\"archive_tip\":" + ARCHIVE_TIP + "}");
            return;
        }

        // Direct address lookup: ?addrs=Mx...,0x...  (scan any address, not just your own keys)
        String addrsParam = paramValue(query, "addrs");
        if (addrsParam != null && !addrsParam.trim().isEmpty()) {
            handleAddrs(ex, addrsParam);
            return;
        }

        String keysParam = paramValue(query, "keys");
        if (keysParam == null || keysParam.trim().isEmpty()) {
            send(ex, 400, "{\"status\":false,\"error\":\"no keys parameter\"}");
            return;
        }

        String[] pks = keysParam.split(",");
        if (pks.length > MAX_KEYS) {
            send(ex, 400, "{\"status\":false,\"error\":\"too many keys\"}");
            return;
        }

        JSONArray out = new JSONArray();
        for (String pkraw : pks) {
            String pk = pkraw.trim();
            if (pk.isEmpty()) continue;
            // Validate shape — a default-address script hashes any string, so without this a
            // malformed key would derive a bogus address and silently return "0 uses" (reads as safe).
            if (!PUBKEY.matcher(pk).matches()) {
                JSONObject bad = new JSONObject();
                bad.put("publickey", pk);
                bad.put("error", "not a valid public key (expected 0x + 64 hex)");
                out.add(bad);
                continue;
            }
            String address, miniaddress;
            try {
                Address ad = new Address("RETURN SIGNEDBY(" + pk + ")");
                address = ad.getAddressData().to0xString();
                miniaddress = ad.getMinimaAddress();
            } catch (Exception e) {
                JSONObject bad = new JSONObject();
                bad.put("publickey", pk);
                bad.put("error", "could not derive address");
                out.add(bad);
                continue;
            }
            long[] v = INDEX.get(address.toUpperCase());
            JSONObject j = new JSONObject();
            j.put("publickey", pk);
            j.put("address", address);
            j.put("miniaddress", miniaddress);
            j.put("spend_blocks", v == null ? 0 : v[0]);
            j.put("spent_coins", v == null ? 0 : v[1]);
            j.put("firstblock", v == null ? -1 : v[2]);
            j.put("lastblock", v == null ? -1 : v[3]);
            out.add(j);
        }

        JSONObject resp = new JSONObject();
        resp.put("status", true);
        resp.put("archive_tip", ARCHIVE_TIP);
        resp.put("keys", out);
        send(ex, 200, resp.toString());
    }

    static void handleAddrs(HttpExchange ex, String addrsParam) throws IOException {
        String[] addrs = addrsParam.split(",");
        if (addrs.length > MAX_KEYS) { send(ex, 400, "{\"status\":false,\"error\":\"too many addresses\"}"); return; }

        JSONArray out = new JSONArray();
        for (String raw : addrs) {
            String input = raw.trim();
            if (input.isEmpty()) continue;
            String hex, mini;
            try {
                if (input.toLowerCase().startsWith("mx")) hex = Address.convertMinimaAddress(input).to0xString();
                else hex = new MiniData(input).to0xString();
                mini = new Address(new MiniData(hex)).getMinimaAddress();
            } catch (Exception e) {
                JSONObject bad = new JSONObject();
                bad.put("input", input);
                bad.put("error", "not a valid Mx or 0x address");
                out.add(bad);
                continue;
            }
            long[] v = INDEX.get(hex.toUpperCase());
            JSONObject j = new JSONObject();
            j.put("input", input);
            j.put("address", hex);
            j.put("miniaddress", mini);
            j.put("spend_blocks", v == null ? 0 : v[0]);
            j.put("spent_coins", v == null ? 0 : v[1]);
            j.put("firstblock", v == null ? -1 : v[2]);
            j.put("lastblock", v == null ? -1 : v[3]);
            out.add(j);
        }
        JSONObject resp = new JSONObject();
        resp.put("status", true);
        resp.put("archive_tip", ARCHIVE_TIP);
        resp.put("addresses", out);
        send(ex, 200, resp.toString());
    }

    // Reuse check: GET /reuse?addrs=Mx|0x,...  -> per-address known-reuse status.
    // Returns public facts only (reused / count / balance) — no signatures.
    static void handleReuse(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Content-Type", "application/json");
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getRawQuery();

        if (path.endsWith("/health")) {
            send(ex, 200, "{\"status\":true,\"reused_addresses\":" + REUSE.size() + "}");
            return;
        }
        String addrsParam = paramValue(query, "addrs");
        if (addrsParam == null || addrsParam.trim().isEmpty()) {
            send(ex, 400, "{\"status\":false,\"error\":\"no addrs parameter\"}");
            return;
        }
        String[] addrs = addrsParam.split(",");
        if (addrs.length > MAX_KEYS) { send(ex, 400, "{\"status\":false,\"error\":\"too many addresses\"}"); return; }

        Map<String, long[]> reuse = REUSE; // snapshot (volatile)
        JSONArray out = new JSONArray();
        for (String raw : addrs) {
            String input = raw.trim();
            if (input.isEmpty()) continue;
            String hex, mini;
            try {
                if (input.toLowerCase().startsWith("mx")) hex = Address.convertMinimaAddress(input).to0xString();
                else hex = new MiniData(input).to0xString();
                mini = new Address(new MiniData(hex)).getMinimaAddress();
            } catch (Exception e) {
                JSONObject bad = new JSONObject();
                bad.put("input", input);
                bad.put("error", "not a valid Mx or 0x address");
                out.add(bad);
                continue;
            }
            long[] v = reuse.get(hex.toUpperCase());
            JSONObject j = new JSONObject();
            j.put("input", input);
            j.put("address", hex);
            j.put("miniaddress", mini);
            j.put("reused", v != null);
            j.put("reuse_count", v == null ? 0 : v[0]);
            j.put("balance", v == null ? 0 : v[1]);
            out.add(j);
        }
        JSONObject resp = new JSONObject();
        resp.put("status", true);
        resp.put("reused_total", reuse.size());
        resp.put("results", out);
        send(ex, 200, resp.toString());
    }

    static String paramValue(String query, String name) {
        if (query == null) return null;
        for (String kv : query.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(name)) {
                return java.net.URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
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
