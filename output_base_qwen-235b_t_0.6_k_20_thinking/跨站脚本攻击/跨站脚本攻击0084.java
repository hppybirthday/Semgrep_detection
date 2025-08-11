package com.example.vulnerableapp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/comment")
public class CommentServlet extends HttpServlet {
    private static List<String> comments = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String comment = request.getParameter("comment");
        
        // 尝试防御：移除<script>标签（存在漏洞：大小写绕过/嵌套绕过）
        if (comment != null && !comment.isEmpty()) {
            // 错误示范：仅过滤小写<script>标签
            comment = comment.replace("<script>", "").replace("</script>", "");
            
            // 漏洞点：未处理其他注入方式（如事件属性）
            comments.add(comment);
        }
        
        response.sendRedirect("comments.jsp");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("comments", comments);
        request.getRequestDispatcher("comments.jsp").forward(request, response);
    }
}

// comments.jsp 内容
<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="java.util.List" %>
<html>
<head>
    <title>Vulnerable Comments</title>
    <style>.comment { margin: 10px 0; padding: 8px; background: #f0f0f0; }</style>
</head>
<body>
    <h2>User Comments</h2>
    <form method="post">
        <textarea name="comment" required></textarea><br>
        <button type="submit">Post Comment</button>
    </form>
    
    <!-- 漏洞点：未转义直接输出用户内容 -->
    <% List<String> comments = (List<String>) request.getAttribute("comments"); %>
    <% if (comments != null) { %>
        <% for (String c : comments) { %>
            <div class="comment"><%= c %></div>  <!-- 漏洞位置 -->
        <% } %>
    <% } %>
</body>
</html>