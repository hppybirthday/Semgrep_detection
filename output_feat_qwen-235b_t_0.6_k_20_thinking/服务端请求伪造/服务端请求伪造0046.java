import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 移动应用后端图片处理接口
 * 快速原型开发风格
 */
public class ImageProcessorServlet extends HttpServlet {
    private static final String STORAGE_PATH = "/var/www/images/";
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 模拟移动客户端传递的图片URL参数
        String imageUrl = request.getParameter("url");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }
        
        try {
            // 存在漏洞的URL处理
            URL url = new URL(imageUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                // 读取图片内容并保存到存储系统
                InputStream inputStream = conn.getInputStream();
                String fileName = extractFileName(imageUrl);
                saveToStorage(inputStream, fileName);
                response.getWriter().println("Image processed: " + fileName);
            } else {
                // 失败时仅记录日志
                System.err.println("Failed to fetch image: " + conn.getResponseMessage());
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        } catch (Exception e) {
            System.err.println("SSRF Vulnerability Triggered: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    
    // 模拟提取文件名
    private String extractFileName(String url) {
        return url.substring(url.lastIndexOf('/') + 1);
    }
    
    // 模拟保存到存储系统
    private void saveToStorage(InputStream inputStream, String fileName) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(STORAGE_PATH + fileName)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }
    
    // 模拟应用入口
    public static void main(String[] args) {
        // 假设部署在Tomcat等容器中
        System.out.println("ImageProcessorServlet running on port 8080");
    }
}