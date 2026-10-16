import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.minima.objects.Address;

/**
 * rootkey -> address helper for the reuse harvester.
 * Reads root public keys (0x...) from stdin (one per line), prints
 *   <rootkey>\t<0x-address>\t<Mx-address>
 * deriving the default address exactly as Minima does: Address("RETURN SIGNEDBY(<rootkey>)").
 * Public keys only — no signatures.
 */
public class ReuseAddr {
    public static void main(String[] args) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String rk;
        while ((rk = br.readLine()) != null) {
            rk = rk.trim();
            if (rk.isEmpty()) continue;
            try {
                Address ad = new Address("RETURN SIGNEDBY(" + rk + ")");
                System.out.println(rk + "\t" + ad.getAddressData().to0xString() + "\t" + ad.getMinimaAddress());
            } catch (Exception e) {
                System.out.println(rk + "\tERR\tERR");
            }
        }
    }
}
