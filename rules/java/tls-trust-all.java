// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class TlsFixture {
    TrustManager tm = new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) { }
        // ruleid: shieldgate.java.tls-trust-all
        public void checkServerTrusted(X509Certificate[] c, String a) { }
        public X509Certificate[] getAcceptedIssuers() { return null; }
    };

    HostnameVerifier hv = new HostnameVerifier() {
        // ruleid: shieldgate.java.tls-trust-all
        public boolean verify(String host, SSLSession s) { return true; }
    };

    // ruleid: shieldgate.java.tls-trust-all
    HostnameVerifier hv2 = (h, s) -> true;

    // ok: shieldgate.java.tls-trust-all
    HostnameVerifier ok = HttpsURLConnection.getDefaultHostnameVerifier();
}
