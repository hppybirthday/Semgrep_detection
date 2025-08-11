package com.example.vulnerableapp;

import java.io.*;
import java.util.Base64;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.logging.Logger;

/**
 * 模拟存在不安全反序列化漏洞的Web应用控制器
 * 用于处理用户配置文件上传功能
 */
public class UserProfileServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger("UserProfileServlet");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 模拟接收base64编码的序列化数据
        String serializedData = request.getParameter("profile");
        if (serializedData == null || serializedData.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing profile data");
            return;
        }

        try {
            // 危险的反序列化操作（漏洞点）
            Object user = deserialize(Base64.getDecoder().decode(serializedData));
            
            // 防御式编程尝试：类型检查
            if (!(user instanceof UserProfile)) {
                logger.warning("Invalid object type received");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data format");
                return;
            }

            // 正常业务逻辑处理
            UserProfile profile = (UserProfile) user;
            logger.info("Received profile for user: " + profile.getUsername());
            response.getWriter().write("Profile received successfully");
            
        } catch (Exception e) {
            logger.severe("Deserialization error: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Processing error");
        }
    }

    /**
     * 不安全的反序列化方法
     */
    private Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    /**
     * 可序列化的用户配置类
     */
    public static class UserProfile implements Serializable {
        private String username;
        private String email;
        private transient String sessionToken; // 敏感字段

        public UserProfile(String username, String email) {
            this.username = username;
            this.email = email;
        }

        // Getters and setters
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
}

/*
Web.xml配置示例：
<servlet>
    <servlet-name>UserProfileServlet</servlet-name>
    <servlet-class>com.example.vulnerableapp.UserProfileServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>UserProfileServlet</servlet-name>
    <url-pattern>/uploadProfile</url-pattern>
</servlet-mapping>
*/