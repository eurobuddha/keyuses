import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.minima.objects.base.MiniData;
import org.minima.objects.keys.TreeKey;
import org.minima.objects.keys.Signature;
import org.minima.objects.keys.SignatureProof;
// NOTE: in the block-as-keyuses jar MMRProof moved to org.minima.objects.mmr (the
// server's production jar still has org.minima.database.mmr — scanners keep that).
import org.minima.objects.mmr.MMRProof;

/**
 * Offline decoder calibration, BOTH key shapes. Build a TreeKey (classic 64/3 and
 * block-as-keyuses 128/4), set a KNOWN leaf index via setUses(), sign, and check the
 * decoder recovers that exact index from the proof chunks — direct and after the same
 * serialization round-trip the archive uses. No wallet, no DB. Run against the
 * block-as-keyuses jar (scanner/minima-blockkeyuses.jar); the stock jar can only
 * build 64/3 trees via createDefault, but the explicit constructor takes any shape.
 */
public class CalibrateDecoder {
    public static void main(String[] args) {
        byte[] sd = new byte[32]; new SecureRandom().nextBytes(sd);
        MiniData seed = new MiniData(sd);
        byte[] dd = new byte[32]; new SecureRandom().nextBytes(dd);
        MiniData data = new MiniData(dd);

        int fails = 0;
        fails += run(new TreeKey(seed, 64, 3), "classic 64/3",
                new int[]{0,1,2,3,5,63,64,65,127,128,200,4095,4096,4097,12345,100000,262143}, data);
        fails += run(new TreeKey(seed, 128, 4), "block-as-keyuses 128/4",
                new int[]{0,1,2,127,128,129,16383,16384,262143,262144,12345678,268435455}, data);

        System.out.println(fails == 0
            ? "\nVALIDATED: decoder reproduces the exact leaf index for every test in both shapes, direct and after serialization."
            : "\nFAILED: " + fails + " mismatches.");
        System.exit(fails == 0 ? 0 : 1);
    }

    static int run(TreeKey tk, String label, int[] tests, MiniData data) {
        int fails = 0;
        System.out.println("=== " + label + " ===");
        System.out.println("idx       | decoded(direct) | decoded(serialized round-trip) | result");
        for (int X : tests) {
            tk.setUses(X);
            Signature sig = tk.sign(data);

            long direct = recover(sig);

            // Round-trip through the SAME serialization the archive uses.
            long roundtrip;
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                sig.writeDataStream(dos);
                dos.flush();
                MiniData ser = new MiniData(baos.toByteArray());
                Signature back = Signature.convertMiniDataVersion(ser);
                roundtrip = recover(back);
            } catch (Exception e) {
                roundtrip = -999;
            }

            boolean ok = (direct == X) && (roundtrip == X);
            if (!ok) fails++;
            System.out.println(String.format("%9d | %15d | %30d | %s",
                    X, direct, roundtrip, ok ? "OK" : "*** WRONG ***"));
        }
        return fails;
    }

    /** identical math to KeyUseScanner.recoverLeafIndex: kpl = 2^prooflen per level */
    static long recover(Signature sig) {
        ArrayList<SignatureProof> ps = sig.getAllSignatureProofs();
        long idx = 0;
        for (SignatureProof sp : ps) {
            MMRProof pr = sp.getProof();
            int len = pr.getProofLength();
            int pos = 0;
            for (int i = 0; i < len; i++) {
                if (pr.getProofChunk(i).isLeft()) pos |= (1 << i);
            }
            idx = idx * (1L << len) + pos;
        }
        return idx;
    }
}
