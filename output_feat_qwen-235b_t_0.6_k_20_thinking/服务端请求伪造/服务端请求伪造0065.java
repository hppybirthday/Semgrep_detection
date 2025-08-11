import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SSRFCrawler extends HttpServlet {
    private String targetUri;
    private String storagePath;

    @Override
    public void init() throws ServletException {
        try {
            // 元编程特征：通过反射动态获取配置参数
            Class<?> configClass = Class.forName("com.example.Config");
            Method getUri = configClass.getMethod("getImportUri");
            Method getPath = configClass.getMethod("getStoragePath");
            
            // 漏洞触发点：未经验证的用户输入
            this.targetUri = (String) getUri.invoke(null);
            this.storagePath = (String) getPath.invoke(null);
            
            // 动态构造URL（错误示范）
            String fullUrl = "http:" + targetUri;
            
            // 发起危险请求
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            // 模拟文件下载
            if (conn.getResponseCode() == 200) {
                try (InputStream in = conn.getInputStream();
                     FileOutputStream out = new FileOutputStream(storagePath + "metadata.bin")) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }
            }
            
        } catch (Exception e) {
            throw new ServletException("Initialization failed: " + e.getMessage());
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        try {
            // 元编程特征：动态响应生成
            Class<?> responseClass = Class.forName("com.example.ResponseHandler");
            Method handle = responseClass.getMethod("sendMetadata", HttpServletResponse.class);
            handle.invoke(null, resp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 模拟内部配置类（实际可能来自外部配置文件）
    public static class Config {
        public static String getImportUri() {
            // 模拟用户输入污染点
            return System.getProperty("user.import.uri", "//localhost:8080/data.json");
        }
        
        public static String getStoragePath() {
            return System.getProperty("storage.path", "/var/data/");
        }
    }
}