package com.example.chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/send")
public class ChatServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Map<String, String> chatHistory = new HashMap<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String user = request.getParameter("user");
        String message = request.getParameter("message");
        
        // 处理图片消息
        if (message.startsWith("[img]") && message.endsWith("[/img]")) {
            String imageUrl = message.substring(5, message.length()-6);
            String content = fetchImageContent(imageUrl); // Vulnerable point
            chatHistory.put(user, "[img]" + content + "[/img]");
        } else {
            chatHistory.put(user, message);
        }
        
        response.getWriter().write("Message sent");
    }

    private String fetchImageContent(String imageUrl) {
        StringBuilder content = new StringBuilder();
        
        try {
            URL url = new URL(imageUrl);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()));
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
        } catch (Exception e) {
            return "Error loading image";
        }
        
        return content.toString();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("application/json");
        StringBuilder json = new StringBuilder("{\\"messages\\":[");
        
        for (Map.Entry<String, String> entry : chatHistory.entrySet()) {
            json.append(String.format("{\\"user\\":\\"%s\\",\\"message\\":\\"%s\\"},",
                entry.getKey(), entry.getValue()));
        }
        
        if (chatHistory.size() > 0) {
            json.setLength(json.length() - 1);
        }
        
        json.append("]}");
        response.getWriter().write(json.toString());
    }
}