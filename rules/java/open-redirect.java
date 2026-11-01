// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import javax.servlet.http.*;

public class RedirectFixture extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String next = req.getParameter("next");
        // ruleid: shieldgate.java.open-redirect
        resp.sendRedirect(next);
        // ok: shieldgate.java.open-redirect
        resp.sendRedirect("/home");
    }
}
