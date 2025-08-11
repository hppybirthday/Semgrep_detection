import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.io.IOUtils;

public class FileEncryptorServlet extends HttpServlet {
    private static final String ENCRYPTION_KEY = "secret_key_123";
    private static final String INTERNAL_STORAGE_PATH = "/var/secure_storage/";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String action = request.getParameter("action");
        String url = request.getParameter("url");
        String password = request.getParameter("password");
        
        if ("encrypt".equals(action) && url != null && password != null) {
            try {
                // 漏洞点：直接使用用户提供的URL发起请求
                URL targetUrl = new URL(url);
                HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
                connection.setRequestMethod("GET");
                
                if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    String fileName = UUID.randomUUID().toString() + ".enc";
                    String filePath = INTERNAL_STORAGE_PATH + fileName;
                    
                    try (InputStream in = connection.getInputStream();
                         OutputStream out = new FileOutputStream(filePath)) {
                        
                        // 模拟加密过程
                        byte[] data = IOUtils.toByteArray(in);
                        byte[] encrypted = encryptData(data, password);
                        out.write(encrypted);
                    }
                    
                    // 返回文件元数据
                    response.getWriter().write(String.format("{\\"file\\":\\"%s\\",\\"size\\":%d}\
", 
                                            fileName, encrypted.length));
                }
                
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            }
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    private byte[] encryptData(byte[] data, String password) {
        // 简化加密逻辑（实际应使用安全算法）
        byte[] key = (password + ENCRYPTION_KEY).substring(0, 16).getBytes();
        byte[] encrypted = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            encrypted[i] = (byte)(data[i] ^ key[i % key.length]);
        }
        return encrypted;
    }

    // 模拟支付通知处理的危险方法
    public void processPaymentNotification(String ip) {
        try {
            // 危险的URL拼接方式
            URL internalUrl = new URL("http://payment-service/internal?ip=" + ip + "&json=true");
            HttpURLConnection conn = (HttpURLConnection) internalUrl.openConnection();
            conn.getInputStream().close(); // 忽略响应处理
        } catch (Exception e) {
            // 日志记录缺失
        }
    }
}