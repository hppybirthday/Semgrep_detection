import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerablePingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String host = request.getParameter("host");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        out.println("<h2>Ping Result:</h2>");
        
        if (host == null || host.isEmpty()) {
            out.println("<p>No host provided</p>");
            return;
        }
        
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ping -c 1 " + host);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            
            out.println("<pre>");
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
            out.println("</pre>");
            
        } catch (Exception e) {
            out.println("<p>Error executing command: " + e.getMessage() + "</p>");
        }
        
        out.println("<form method='get'>");
        out.println("Host: <input type='text' name='host'>");
        out.println("<input type='submit' value='Ping'>");
        out.println("</form>");
        out.println("</body></html>");
    }
}