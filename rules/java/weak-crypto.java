// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class CryptoFixture {
    public void bad() throws Exception {
        // ruleid: shieldgate.java.weak-cipher
        Cipher c1 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: shieldgate.java.weak-cipher
        Cipher c2 = Cipher.getInstance("DES");
        // ruleid: shieldgate.java.weak-hash
        MessageDigest md = MessageDigest.getInstance("MD5");
    }

    public void good() throws Exception {
        // ok: shieldgate.java.weak-cipher
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        // ok: shieldgate.java.weak-hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
