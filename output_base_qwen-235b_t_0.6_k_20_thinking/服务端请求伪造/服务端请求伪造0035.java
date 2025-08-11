import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class TaskImporter extends HttpServlet {
    private Object executeExternalCall(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        if (conn.getResponseCode() == 200) {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            return parseResponse(response.toString());
        }
        return null;
    }

    private Object parseResponse(String response) throws Exception {
        Class<?> clazz = Class.forName("com.example.TaskResponse");
        Method method = clazz.getMethod("parse", String.class);
        return method.invoke(clazz.newInstance(), response);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            String importUrl = req.getParameter("import_url");
            if (importUrl == null || importUrl.isEmpty()) {
                resp.sendError(400, "Missing import URL");
                return;
            }

            // 元编程动态调用
            Class<?> importerClass = Class.forName("com.example.TaskImporter");
            Method method = importerClass.getMethod("executeExternalCall", String.class);
            Object result = method.invoke(this, importUrl);

            resp.setContentType("application/json");
            PrintWriter out = resp.getWriter();
            out.println(result.toString());
            out.close();
        } catch (Exception e) {
            throw new ServletException("SSRF Vulnerability Exploited", e);
        }
    }
}

// 模拟的内部服务接口
class InternalTaskService {
    public static String getInternalData() {
        return "INTERNAL_SECRET_DATA";
    }
}

// 模拟的元数据类
class TaskResponse {
    public static TaskResponse parse(String json) {
        return new TaskResponse();
    }
    public String toString() {
        return "{\\"status\\":\\"success\\"}";
    }
}