// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import java.io.PrintWriter;
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class XssFixture extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String q = req.getParameter("q");
        PrintWriter out = resp.getWriter();
        // ruleid: shieldgate.java.xss-servlet-writer
        out.println("<h1>Results for " + q + "</h1>");
        // ok: shieldgate.java.xss-servlet-writer
        out.println("<h1>Results for " + Encode.forHtml(q) + "</h1>");
        try (PrintWriter log = new PrintWriter("/tmp/audit.log")) {
            // ok: shieldgate.java.xss-servlet-writer
            log.println("query: " + q);
        }
    }
}
