package com.example.xss;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/ad")
public class AdvertisementServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static List<String> ads = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 模拟防御式编程中的错误验证
        String userInput = request.getParameter("adContent");
        
        // 错误的过滤逻辑（可被绕过）
        if (userInput != null && userInput.length() < 200) {
            // 仅替换简单标签但保留危险属性
            String sanitized = userInput.replace("<script>", "&lt;script&gt;");
            ads.add(sanitized);
        }
        
        response.sendRedirect("ads.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("ads", ads);
        request.getRequestDispatcher("ads.jsp").forward(request, response);
    }
}

// === ads.jsp ===
<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="java.util.List" %>
<%@ page import="com.example.xss.AdvertisementServlet" %>
<html>
<head><title>广告展示</title></head>
<body>
    <h1>用户广告展示</h1>
    
    <form action="ad" method="post">
        <textarea name="adContent" maxlength="200"></textarea>
        <input type="submit" value="发布广告">
    </form>

    <div id="ads">
        <% List<String> ads = (List<String>) request.getAttribute("ads"); %>
        <% if (ads != null) { %>
            <% for (String ad : ads) { %>
                <div class="ad-content">
                    <!-- 危险的HTML渲染 -->
                    <%= ad %>
                </div>
            <% } %>
        <% } %>
    </div>
</body>
</html>