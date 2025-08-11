import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class ChatServlet extends HttpServlet {
    private List<String> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String message = request.getParameter("message");
        if (message != null && !message.trim().isEmpty()) {
            messages.add(message);
        }
        response.sendRedirect("chat.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setAttribute("messages", messages);
        RequestDispatcher dispatcher = request.getRequestDispatcher("chat.jsp");
        dispatcher.forward(response.getWriter());
    }
}

// chat.jsp
<%@ page import="java.util.List" %>
<!DOCTYPE html>
<html>
<head><title>Chat App</title></head>
<body>
    <h1>Chat Messages</h1>
    <% List<String> messages = (List<String>) request.getAttribute("messages"); %>
    <% if (messages != null) { %>
        <% for (String msg : messages) { %>
            <div><%= msg %></div>  <!-- 漏洞点：直接输出用户输入 -->
        <% } %>
    <% } %>
    
    <form action="ChatServlet" method="POST">
        <input type="text" name="message" placeholder="Enter message">
        <button type="submit">Send</button>
    </form>
</body>
</html>