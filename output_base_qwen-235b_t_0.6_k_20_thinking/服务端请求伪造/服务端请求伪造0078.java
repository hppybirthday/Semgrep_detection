import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.*;

public class SSRFDemo extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String urlParam = request.getParameter("url");
        if (urlParam == null || urlParam.isEmpty()) {
            response.getWriter().write("Missing URL parameter");
            return;
        }
        
        try {
            URL target = new URL(urlParam);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            conn.disconnect();
            
            response.setContentType("text/html");
            response.getWriter().write("<h3>Preview Content:</h3><pre>" + content.toString() + "</pre>");
            
        } catch (Exception e) {
            response.getWriter().write("Error fetching URL: " + e.getMessage());
        }
    }
}

/*
部署说明：
1. web.xml配置：
<servlet>
    <servlet-name>SSRFDemo</servlet-name>
    <servlet-class>SSRFDemo</servlet-class>
</servlet>
<servlet-mapping>
    <url-pattern>/preview</url-pattern>
</servlet-mapping>

2. 访问示例：
http://app.com/preview?url=https://example.com
攻击示例：
http://app.com/preview?url=file:///etc/passwd
http://app.com/preview?url=http://169.254.169.254/latest/meta-data/
*/