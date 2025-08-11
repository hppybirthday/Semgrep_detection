package com.example.vulnerableapp;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 不安全反序列化漏洞示例
 * 模拟用户配置反序列化场景
 */
@WebServlet("/loadPreferences")
public class PreferencesLoader extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 从请求参数获取Base64编码的序列化数据
        String encodedData = request.getParameter("prefs");
        if (encodedData == null || encodedData.isEmpty()) {
            response.getWriter().write("Missing preferences data");
            return;
        }
        
        try {
            // 不安全的反序列化过程
            byte[] decodedBytes = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            
            if (obj instanceof UserPreferences) {
                UserPreferences prefs = (UserPreferences) obj;
                response.getWriter().write("Preferences loaded successfully");
                // 模拟使用偏好数据
                processPreferences(prefs);
            } else {
                response.getWriter().write("Invalid preferences format");
            }
            
        } catch (Exception e) {
            response.getWriter().write("Error processing preferences: " + e.getMessage());
        }
    }
    
    private void processPreferences(UserPreferences prefs) {
        // 模拟使用用户偏好数据
        System.out.println("Theme: " + prefs.getTheme());
        System.out.println("Language: " + prefs.getLanguage());
        // 假设这里存在敏感操作
        if (prefs.isAdmin()) {
            executeAdminTask(prefs.getAdminCommand());
        }
    }
    
    private void executeAdminTask(String command) {
        // 模拟执行管理命令（实际可能使用ProcessBuilder等）
        System.out.println("Executing admin command: " + command);
    }
}

// 可序列化的用户偏好类
class UserPreferences implements java.io.Serializable {
    private String theme;
    private String language;
    private boolean admin;
    private String adminCommand;
    
    // Getters and setters
    public String getTheme() { return theme; }
    public void setTheme(String theme) { this.theme = theme; }
    
    public String getLanguage() { return language; }
    public void setLanguage(String language) { this.language = language; }
    
    public boolean isAdmin() { return admin; }
    public void setAdmin(boolean admin) { this.admin = admin; }
    
    public String getAdminCommand() { return adminCommand; }
    public void setAdminCommand(String adminCommand) { this.adminCommand = adminCommand; }
}