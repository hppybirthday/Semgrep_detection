package com.example.vulnerableapp;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

@WebServlet("/submitProfile")
public class ProfileServlet extends HttpServlet {
    private JavaMailSender mailSender; // 模拟邮件发送组件

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String comment = request.getParameter("comment");
        String email = request.getParameter("email");
        
        // 危险操作：直接将用户输入设置到request属性
        request.setAttribute("username", username);
        request.setAttribute("comment", comment);
        
        // 存储型XSS：将用户输入持久化（模拟数据库存储）
        storeUserProfile(username, comment, email);
        
        // 反射型XSS：直接输出到响应
        response.getWriter().println(
            "<html><body>欢迎用户：" + username + "</body></html>"
        );
        
        // 邮件上下文XSS：构造HTML邮件内容
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mailSender.createMimeMessage(), true);
            helper.setTo(email);
            helper.setSubject("欢迎加入");
            // 危险操作：直接注入用户输入到HTML邮件内容
            String emailContent = "<div>欢迎," + username + "!<script>alert(document.cookie)</script></div>";
            helper.setText(emailContent, true); // 第二个参数true表示启用HTML
            mailSender.send(helper.getMimeMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 模拟数据库存储
    private void storeUserProfile(String username, String comment, String email) {
        // 实际存储逻辑（忽略SQL注入漏洞）
        System.out.println("Storing: " + username + ", " + comment + ", " + email);
    }
}

/* 
JSP视图层（profile.jsp）:
<html>
<body>
    <h1>用户资料</h1>
    <!-- 危险操作：EL表达式直接输出用户输入 -->
    <p>用户名: ${username}</p>
    <div class="comment">
        <!-- 危险操作：未过滤的HTML内容输出 -->
        ${comment}
    </div>
    
    <!-- 表单提交入口 -->
    <form method="post">
        <input name="username">
        <textarea name="comment"></textarea>
        <input type="email" name="email">
        <button type="submit">提交</button>
    </form>
</body>
</html>
*/