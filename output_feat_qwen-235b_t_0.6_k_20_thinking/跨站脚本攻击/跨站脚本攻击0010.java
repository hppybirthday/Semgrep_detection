import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DataCleanerServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String userInput = request.getParameter("name");
        if (userInput == null) {
            userInput = "Guest";
        }
        
        // 模拟数据清洗过程（存在漏洞的关键点）
        String cleanedData = "";
        for (int i = 0; i < userInput.length(); i++) {
            char c = userInput.charAt(i);
            // 错误的过滤逻辑：只过滤尖括号但保留其他特殊字符
            if (c == '<' || c == '>') {
                cleanedData += ""; // 移除尖括号
            } else {
                cleanedData += c; // 直接拼接其他字符
            }
        }
        
        // 将用户数据存储到请求属性（未转义）
        request.setAttribute("username", cleanedData);
        
        // 转发到JSP视图（使用危险的EL表达式）
        RequestDispatcher dispatcher = request.getRequestDispatcher("/welcome.jsp");
        dispatcher.forward(request, response);
    }
}

// welcome.jsp 内容（HTML文本上下文）
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Welcome</title></head>
<body>
    <h1>Welcome, ${username}</h1> <!-- 漏洞触发点 -->
    <p>Current time: <%= new java.util.Date() %></p>
</body>
</html>