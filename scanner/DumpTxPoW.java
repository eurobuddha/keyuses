import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import org.minima.objects.TxPoW;
import org.minima.objects.Witness;
import org.minima.objects.base.MiniData;

public class DumpTxPoW {
    public static void main(String[] args) throws Exception {
        boolean dumpAll = args.length > 0 && args[0].equals("--all");
        Class.forName("org.h2.Driver");
        Connection conn = DriverManager.getConnection("jdbc:h2:/tmp/txpow_copy;MODE=MySQL", "SA", "");

        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT id, txpowid, isblock, istransaction, parentid, timemilli, isrelevant FROM txpow ORDER BY id");

        int blocks = 0, txns = 0, withBody = 0, withSig = 0, total = 0;
        while (rs.next()) {
            total++;
            long id = rs.getLong("id");
            String txpowid = rs.getString("txpowid");
            boolean isblk = rs.getInt("isblock") == 1;
            boolean istxn = rs.getInt("istransaction") == 1;
            long tm = rs.getLong("timemilli");
            boolean relevant = rs.getInt("isrelevant") == 1;

            if (isblk) blocks++;
            if (istxn) txns++;

            // Fetch the blob
            Statement st2 = conn.createStatement();
            ResultSet rs2 = st2.executeQuery("SELECT txpowdata FROM txpow WHERE id=" + id);
            if (rs2.next()) {
                byte[] data = rs2.getBytes("txpowdata");
                try {
                    MiniData md = new MiniData(data);
                    TxPoW txp = TxPoW.convertMiniDataVersion(md);
                    if (txp != null && txp.hasBody()) {
                        withBody++;
                        Witness w = txp.getWitness();
                        Witness bw = txp.getBurnWitness();
                        int sigs = (w != null ? w.getAllSignatures().size() : 0)
                                 + (bw != null ? bw.getAllSignatures().size() : 0);
                        if (sigs > 0) withSig++;

                        if (sigs > 0 || dumpAll) {
                            System.out.println("id=" + id + " txpowid=" + txpowid
                                + " block=" + isblk + " txn=" + istxn
                                + " relevant=" + relevant + " sigs=" + sigs
                                + " blknum=" + txp.getBlockNumber());
                            if (sigs > 0) {
                                if (w != null && w.getAllSignatures().size() > 0) {
                                    System.out.println("  witness sigs: " + w.getAllSignatures().size());
                                    for (int i = 0; i < w.getAllSignatures().size(); i++) {
                                        System.out.println("    sig[" + i + "] root=" + w.getAllSignatures().get(i).getRootPublicKey());
                                    }
                                }
                                if (bw != null && bw.getAllSignatures().size() > 0) {
                                    System.out.println("  burnwitness sigs: " + bw.getAllSignatures().size());
                                    for (int i = 0; i < bw.getAllSignatures().size(); i++) {
                                        System.out.println("    burnsig[" + i + "] root=" + bw.getAllSignatures().get(i).getRootPublicKey());
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    System.out.println("id=" + id + " ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
            rs2.close();
            st2.close();

            if (total % 1000 == 0) {
                System.out.println("... " + total + " rows scanned, " + withSig + " with sigs");
            }
        }
        rs.close();
        st.close();
        conn.close();

        System.out.println("TOTAL: " + total + " rows, " + blocks + " blocks, " + txns + " txns, "
            + withBody + " withBody, " + withSig + " with sigs");
    }
}
