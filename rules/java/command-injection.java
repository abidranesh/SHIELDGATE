// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
public class CmdFixture {
    public void bad(String host) throws Exception {
        // ruleid: shieldgate.java.runtime-exec-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: shieldgate.java.runtime-exec-injection
        new ProcessBuilder("/bin/sh", "-c", "nslookup " + host).start();
    }

    public void good(String host) throws Exception {
        // ok: shieldgate.java.runtime-exec-injection
        new ProcessBuilder("ping", "-c", "1", host).start();
        // ok: shieldgate.java.runtime-exec-injection
        Runtime.getRuntime().exec("uptime");
    }
}
