import java.math.BigInteger;

import org.minima.objects.Address;
import org.minima.objects.base.MiniData;
import org.minima.objects.keys.TreeKey;
import org.minima.utils.BIP39;
import org.minima.utils.Crypto;

/**
 * Golden-vector generator for phrase/derive.test.js.
 * For each test phrase, derives keys 0..3 in BOTH tree shapes using Minima's own classes:
 *   classic          64 keys/level, 3 levels  (what every node did before block-as-keyuses)
 *   block-as-keyuses 128 keys/level, 4 levels (minimaCore -blockaskeyuses, 1.1.2.31-euro4)
 * Prints a JSON object consumed verbatim by the JS test. Compile/run against the
 * block-as-keyuses jar (scanner/minima-blockkeyuses.jar) — its TreeKey accepts any shape.
 *
 *   javac --release 11 -cp scanner/minima-blockkeyuses.jar scanner/DeriveVectors.java
 *   java  -cp scanner/minima-blockkeyuses.jar:scanner DeriveVectors > phrase/derive.vectors.json
 */
public class DeriveVectors {

    static final int NUM_INDICES = 4;
    static final int[][] SHAPES = { {64, 3}, {128, 4} };

    public static void main(String[] args) throws Exception {
        // phrase, anyphrase flag
        Object[][] phrases = {
            { "abandon ability able about above absent absorb abstract absurd abuse access accident "
            + "account accuse achieve acid acoustic acquire across act action actor actress actual", false },
            { "correct horse battery staple eurobuddha test vector", true },
        };

        StringBuilder out = new StringBuilder("{\n  \"vectors\": [\n");
        boolean first = true;
        for (Object[] p : phrases) {
            String phrase  = (String) p[0];
            boolean any    = (Boolean) p[1];
            String hashed  = any ? phrase : BIP39.cleanSeedPhrase(phrase);
            MiniData seed  = BIP39.convertStringToSeed(hashed);

            for (int i = 0; i < NUM_INDICES; i++) {
                MiniData modifier = new MiniData(new BigInteger(Integer.toString(i)));
                MiniData privseed = Crypto.getInstance().hashObjects(seed, modifier);
                for (int[] shape : SHAPES) {
                    TreeKey tk = new TreeKey(privseed, shape[0], shape[1]);
                    Address ad = new Address("RETURN SIGNEDBY(" + tk.getPublicKey().to0xString() + ")");
                    if (!first) out.append(",\n");
                    first = false;
                    out.append("    {\"phrase\": ").append(jstr(phrase))
                       .append(", \"anyphrase\": ").append(any)
                       .append(", \"baseseed\": \"").append(seed.to0xString()).append('"')
                       .append(", \"index\": ").append(i)
                       .append(", \"keysPerLevel\": ").append(shape[0])
                       .append(", \"publickey\": \"").append(tk.getPublicKey().to0xString()).append('"')
                       .append(", \"address\": \"").append(ad.getAddressData().to0xString()).append('"')
                       .append(", \"mx\": \"").append(ad.getMinimaAddress()).append("\"}");
                }
            }
        }
        out.append("\n  ]\n}");
        System.out.println(out);
    }

    static String jstr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
