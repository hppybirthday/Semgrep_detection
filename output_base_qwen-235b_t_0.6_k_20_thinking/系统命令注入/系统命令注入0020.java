import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerablePingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String host = request.getParameter("host");
        if (host == null || host.isEmpty()) {
            out.println("<h3>请输入主机名</h3>");
            return;
        }
        
        out.println("<h3>正在ping主机: " + host + "</h3>");
        out.println("<pre>");
        
        try {
            // 漏洞点：直接拼接用户输入到系统命令
            Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
            while ((line = errorReader.readLine()) != null) {
                out.println("[ERROR] " + line);
            }
            
        } catch (Exception e) {
            out.println("[异常] " + e.getMessage());
        }
        
        out.println("</pre>");
        out.println("<a href=\\"javascript:history.back()\\">返回</a>");
    }
}

/*
web.xml配置示例：
<servlet>
    <servlet-name>PingServlet</servlet-name>
    <servlet-class>VulnerablePingServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>PingServlet</servlet-name>
    <url-pattern>/ping</url-pattern>
</servlet-mapping>
*/