package com.bank.xss.demo;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

@WebServlet("/profile")
public class UserProfileServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Map<String, String> userStore = new HashMap<>();

    static {
        // 模拟数据库初始化数据
        userStore.put("alice", "Alice_Wonderland");
        userStore.put("bob", "Bob's_Journey");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("user");
        if (username == null || username.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing username");
            return;
        }

        String nickname = userStore.getOrDefault(username, "Guest_User");
        
        // 使用Jsoup动态生成HTML（存在漏洞的关键点）
        String template = "<html><body><h1>User Profile</h1>" + 
            "<div id='nickname'>PLACEHOLDER</div>" + 
            "<form method='post'>" + 
            "<input type='text' name='nick' value='" + nickname + "'/>" + 
            "<input type='hidden' name='user' value='" + username + "'/>" + 
            "<button type='submit'>Update</button></form></body></html>";

        Document doc = Jsoup.parse(template);
        Element nickElement = doc.getElementById("nickname");
        
        // 危险操作：直接注入用户数据（绕过Jsoup的自动转义机制）
        // 正确做法应使用nickElement.text(nickname)进行HTML转义
        nickElement.html(nickname);

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.write(doc.html());
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("user");
        String newNick = request.getParameter("nick");
        
        if (username != null && newNick != null) {
            // 存储未过滤的用户输入
            userStore.put(username, newNick);
            
            // 重定向回GET请求显示更新
            response.sendRedirect("profile?user=" + username);
            return;
        }
        
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid input");
    }
}