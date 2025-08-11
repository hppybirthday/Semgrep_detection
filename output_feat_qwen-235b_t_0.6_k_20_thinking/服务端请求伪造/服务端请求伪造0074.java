import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DataCleanerServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String logId = request.getParameter("logId");
        if (logId == null || logId.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing logId parameter");
            return;
        }

        try {
            // 模拟数据清洗流程中的URL解析
            URL targetUrl = new URL("http://internal-log-service/validate?token=" + logId);
            
            // 使用自定义工具类发起请求
            SSRFUtil.validateLogFormat(targetUrl);
            
            // 实际清洗操作（示例：触发SSRF漏洞）
            String result = SSRFUtil.fetchInternalResource(targetUrl);
            
            response.getWriter().write("Data cleaned successfully: " + result);
            
        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server error");
        }
    }
}

class SSRFUtil {
    // 模拟防御式编程中的无效检查
    public static void validateLogFormat(URL url) throws IOException {
        String protocol = url.getProtocol();
        if (!protocol.equals("http") && !protocol.equals("https")) {
            throw new IllegalArgumentException("Only HTTP/HTTPS protocols allowed");
        }
    }

    // 存在漏洞的内部资源访问方法
    public static String fetchInternalResource(URL url) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(url.openStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 模拟日志清洗操作（完全输出响应内容）
                System.out.println("[CLEANED_LOG] " + line);
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}