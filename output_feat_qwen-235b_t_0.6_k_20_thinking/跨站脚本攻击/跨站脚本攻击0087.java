import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class MLModelServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        String input = req.getParameter("data");
        
        // Machine learning model simulation
        String prediction = "";
        if(input != null && !input.isEmpty()) {
            prediction = simulateMLModel(input);
        }
        
        // Vulnerable HTML rendering
        out.println("<html><body>");
        out.println("<h2>Prediction Result:</h2>");
        out.println("<div>Input: " + input + "</div>");  // XSS Vulnerability here
        out.println("<div>Prediction: " + prediction + "</div>");
        out.println("</body></html>");
    }
    
    private String simulateMLModel(String input) {
        // Simple ML simulation logic
        if(input.toLowerCase().contains("malicious")) {
            return "Threat Detected";
        }
        return "Normal Traffic";
    }
}

/*
Web.xml configuration example:
<servlet>
    <servlet-name>MLModelServlet</servlet-name>
    <servlet-class>MLModelServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>MLModelServlet</servlet-name>
    <url-pattern>/predict</url-pattern>
</servlet-mapping>
*/