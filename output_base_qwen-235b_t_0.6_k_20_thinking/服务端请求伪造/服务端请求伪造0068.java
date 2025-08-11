import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String url = req.getParameter("url");
        if(url == null) url = "https://default.example.com";
        
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection)target.openConnection();
            conn.setRequestMethod("GET");
            
            res.setContentType("text/html");
            PrintWriter out = res.getWriter();
            out.println("<html><body>");
            out.println("<h1>Proxy Result:</h1>");
            out.println("<pre>");
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            String inputLine;
            while((inputLine = in.readLine()) != null) {
                out.println(inputLine.replaceAll("[\\s\\S]{1,1000}", "$0<br>"));
            }
            in.close();
            out.println("</pre></body></html>");
            
        } catch (Exception e) {
            res.sendError(500, "Proxy Error: " + e.getMessage());
        }
    }
}

/*
部署描述符示例：
<servlet>
    <servlet-name>VulnerableProxy</servlet-name>
    <servlet-class>VulnerableServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>VulnerableProxy</servlet-name>
    <url-pattern>/proxy</url-pattern>
</servlet-mapping>
*/