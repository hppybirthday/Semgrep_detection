import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatMessageHandler extends HttpServlet {
    // 模拟消息消费者服务层
    public static class MessageConsumer {
        public void processMessage(String content, String notifyUrl) {
            try {
                // 漏洞点：直接拼接用户输入的URL
                URL targetUrl = new URL(notifyUrl);
                HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                
                // 发送消息内容作为请求体
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(content.getBytes("UTF-8"));
                }
                
                // 处理响应并存储结果（如缩略图URL）
                if (connection.getResponseCode() == 200) {
                    try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(connection.getInputStream()))) {
                        String response;
                        while ((response = br.readLine()) != null) {
                            // 模拟存储缩略图URL
                            if (response.contains("thumbnail")) {
                                storeThumbnailUrl(response);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        private void storeThumbnailUrl(String response) {
            // 实际存储逻辑
            System.out.println("Stored thumbnail info: " + response);
        }
    }
    
    // 模拟请求处理
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        try {
            String messageContent = req.getParameter("message");
            String notifyUrl = req.getParameter("notifyUrl");
            
            // 消息验证（存在缺陷的防御）
            if (messageContent == null || messageContent.isEmpty() || 
                notifyUrl == null || notifyUrl.isEmpty()) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            
            // 存在漏洞的消息处理
            new MessageConsumer().processMessage(messageContent, notifyUrl);
            resp.getWriter().write("Message processed");
            
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}