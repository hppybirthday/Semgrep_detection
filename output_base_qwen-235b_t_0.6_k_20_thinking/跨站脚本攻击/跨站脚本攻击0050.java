import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class ChatServlet extends HttpServlet {
    private static List<String> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String user = request.getParameter("user");
        String message = request.getParameter("message");
        
        // 危险操作：直接拼接用户输入到HTML内容中
        String htmlMessage = "<div class='msg'><b>" + user + "</b>: " + message + "</div>";
        messages.add(htmlMessage);
        
        response.sendRedirect("chat.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("messages", messages);
        request.getRequestDispatcher("chat.jsp").forward(request, response);
    }
}

// chat.jsp 内容：
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Chat App</title></head>
<body>
    <h1>Chat Messages</h1>
    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
    <c:forEach items="${messages}" var="msg">
        ${msg}  <!-- 这里直接输出未经处理的HTML内容 -->
    </c:forEach>
    
    <form action="ChatServlet" method="POST">
        User: <input type="text" name="user"><br>
        Message: <input type="text" name="message"><br>
        <input type="submit" value="Send">
    </form>
</body>
</html>