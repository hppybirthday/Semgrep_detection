import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileCryptoServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String action = request.getParameter("action");
        String targetUrl = request.getParameter("url");
        
        if(action == null || targetUrl == null || 
          (!action.equals("encrypt") && !action.equals("decrypt"))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        try {
            // SSRF漏洞点：直接使用用户输入的URL发起请求
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            conn.disconnect();
            
            // 模拟加密/解密操作（实际应包含真实加密逻辑）
            String processedData = processContent(content.toString(), action);
            
            // 返回处理结果
            response.setContentType("text/plain");
            response.getWriter().write(processedData);
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private String processContent(String data, String action) {
        // 模拟加密/解密逻辑
        if(action.equals("encrypt")) {
            return "ENCRYPTED_DATA(" + data.length() + ")";
        } else {
            return "DECRYPTED_DATA(" + data.length() + ")";
        }
    }
}

/*
部署描述符示例：
<servlet>
    <servlet-name>FileCryptoServlet</servlet-name>
    <servlet-class>FileCryptoServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>FileCryptoServlet</servlet-name>
    <url-pattern>/crypto</url-pattern>
</servlet-mapping>
*/