// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import java.io.*;

public class DeserFixture {
    public Object bad(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: shieldgate.java.object-deserialization
        return ois.readObject();
    }

    public Object good(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.Dto;!*"));
        // ok: shieldgate.java.object-deserialization
        return ois.readObject();
    }
}
