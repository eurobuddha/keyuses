import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import org.minima.objects.base.MiniData;
import org.minima.objects.keys.TreeKey;
import org.minima.objects.keys.Signature;
import org.minima.objects.keys.SignatureProof;
import org.minima.database.mmr.MMRProof;

/**
 * Offline decoder calibration. Build a default 64/3 TreeKey, set a KNOWN leaf index
 * via setUses(), sign, and dump the raw per-level positions extracted from the proof
 * chunks vs the expected base-64 digits of the index. From this we read off the exact
 * bit/level mapping. No wallet, no DB.
 */
public class CalibrateDecoder {
    public static void main(String[] args) {
        byte[] sd = new byte[32]; new SecureRandom().nextBytes(sd);
        TreeKey tk = TreeKey.createDefault(new MiniData(sd));
        byte[] dd = new byte[32]; new SecureRandom().nextBytes(dd);
        MiniData data = new MiniData(dd);

        int[] tests = {0,1,2,3,5,63,64,65,127,128,200,4095,4096,4097,12345,100000,262143};
        int fails = 0;
        System.out.println("idx     | decoded(direct) | decoded(serialized round-trip) | result");
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
            System.out.println(String.format("%7d | %15d | %30d | %s",
                    X, direct, roundtrip, ok ? "OK" : "*** WRONG ***"));
        }
        System.out.println(fails == 0
            ? "\nVALIDATED: decoder reproduces the exact leaf index for every test, direct and after serialization."
            : "\nFAILED: " + fails + " mismatches.");
    }

    /** identical math to KeyUseScanner.recoverLeafIndex */
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
            idx = idx * 64 + pos;
        }
        return idx;
    }
}
