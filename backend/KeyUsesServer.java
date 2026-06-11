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
    static long ARCHIVE_TIP = -1;
    static final int MAX_KEYS = 256;

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        int port = Integer.parseInt(a.getOrDefault("port", "3010"));
        String indexFile = a.getOrDefault("index", "coin_index.tsv");

        loadIndex(indexFile);

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/keyaudit", KeyUsesServer::handle);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4));
        server.start();
        System.err.println("KeyUses backend on 127.0.0.1:" + port + " — " + INDEX.size() + " addresses, archive_tip=" + ARCHIVE_TIP);
    }

    static void loadIndex(String path) throws IOException {
        long tip = -1;
        try (java.io.BufferedReader br = Files.newBufferedReader(Paths.get(path), StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty()) continue;
                String[] p = line.split("\t");
                if (p.length < 5) continue;
                long[] v = new long[]{ Long.parseLong(p[1]), Long.parseLong(p[2]), Long.parseLong(p[3]), Long.parseLong(p[4]) };
                INDEX.put(p[0].toUpperCase(), v);
                if (v[3] > tip) tip = v[3];
            }
        }
        ARCHIVE_TIP = tip;
        System.err.println("loaded index: " + INDEX.size() + " addresses, max lastblock=" + tip);
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
            String address;
            try {
                address = new Address("RETURN SIGNEDBY(" + pk + ")").getAddressData().to0xString();
            } catch (Exception e) {
                continue; // skip malformed pubkey
            }
            long[] v = INDEX.get(address.toUpperCase());
            JSONObject j = new JSONObject();
            j.put("publickey", pk);
            j.put("address", address);
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
