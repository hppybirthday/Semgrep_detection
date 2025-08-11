package com.example.chat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@WebServlet("/chat")
public class ChatServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        request.setCharacterEncoding("UTF-8");
        String message = request.getParameter("message");
        HttpSession session = request.getSession();
        
        // 防御式编程尝试：简单过滤script标签（存在绕过风险）
        if (message != null && message.length() > 0) {
            // 错误实现：仅替换大小写script标签
            message = message.replaceAll("(?i)<script.*?>.*?</script>", "");
            
            @SuppressWarnings("unchecked")
            List<String> messages = (List<String>) session.getAttribute("messages");
            if (messages == null) {
                messages = new ArrayList<>();
                session.setAttribute("messages", messages);
            }
            messages.add(message);
        }
        
        response.sendRedirect("chat.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.getRequestDispatcher("chat.jsp").forward(request, response);
    }
}

// chat.jsp 内容
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Chat App</title>
</head>
<body>
    <h2>Chat Messages:</h2>
    <div id="chat">
        <c:forEach items="${sessionScope.messages}" var="msg">
            <div class="message">${msg}</div> <!-- 漏洞触发点：直接输出用户输入 -->
        </c:forEach>
    </div>
    <form action="chat" method="post">
        <input type="text" name="message" placeholder="Type your message...">
        <button type="submit">Send</button>
    </form>
</body>
</html>