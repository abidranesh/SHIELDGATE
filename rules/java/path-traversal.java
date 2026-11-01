// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import java.io.*;
import javax.servlet.http.*;

public class PathFixture extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("file");
        // ruleid: shieldgate.java.path-traversal
        FileInputStream in = new FileInputStream("/srv/files/" + name);
        // ok: shieldgate.java.path-traversal
        FileInputStream in2 = new FileInputStream("/srv/files/static.txt");
    }
}
