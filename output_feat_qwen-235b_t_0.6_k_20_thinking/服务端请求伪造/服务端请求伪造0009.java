import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 高抽象建模风格的接口定义
interface LogOperation {
    String execute(String param) throws Exception;
}

// 日志详情查看操作
class LogDetailCat implements LogOperation {
    @Override
    public String execute(String param) throws Exception {
        String content = new UrlFetcher().fetchContent(param);
        return "<pre>" + content.replaceAll("[<>&"']", "") + "</pre>"; // HTML转义不足
    }
}

// 日志终止操作
class LogKill implements LogOperation {
    @Override
    public String execute(String param) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(param).openConnection();
        conn.setConnectTimeout(1000);
        if(conn.getResponseCode() == 200) {
            return "Log killed successfully";
        }
        return "Kill failed: " + conn.getResponseMessage();
    }
}

// 通用URL请求工具类
class UrlFetcher {
    public String fetchContent(String urlString) throws Exception {
        URL url = new URL(urlString);
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(url.openStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\
");
            }
            return sb.toString();
        }
    }
}

// 模拟Spring MVC控制器
@WebServlet("/joblog/*")
public class JobLogController extends HttpServlet {
    private final Map<String, LogOperation> operations = new HashMap<>();

    public JobLogController() {
        operations.put("logDetailCat", new LogDetailCat());
        operations.put("logKill", new LogKill());
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        
        String pathInfo = req.getPathInfo();
        if (pathInfo == null) return;
        
        String[] parts = pathInfo.split("/");
        if (parts.length < 2) return;
        
        String operationName = parts[1];
        LogOperation operation = operations.get(operationName);
        
        if (operation == null) return;
        
        try {
            String param = req.getParameter("param");
            String result = operation.execute(param);
            resp.getWriter().write(result);
        } catch (Exception e) {
            resp.setStatus(500);
            resp.getWriter().write("Internal error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 模拟启动容器
        Server server = new Server(8080);
        ServletContextHandler context = new ServletContextHandler();
        context.addServlet(JobLogController.class, "/joblog/*");
        server.setHandler(context);
        // ... 启动代码省略 ...
    }
}