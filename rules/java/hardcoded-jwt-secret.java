// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtFixture {
    public String bad(String user) {
        // ruleid: shieldgate.java.hardcoded-jwt-secret
        return JWT.create().withSubject(user).sign(Algorithm.HMAC256("changeit-secret"));
    }

    public String good(String user) {
        // ok: shieldgate.java.hardcoded-jwt-secret
        return JWT.create().withSubject(user).sign(Algorithm.HMAC256(System.getenv("JWT_SECRET")));
    }
}
