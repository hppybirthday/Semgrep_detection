package xss.chat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/chat")
public class ChatServlet extends HttpServlet {
    private static final List<String> messages = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        String msg = req.getParameter("message");
        if (msg != null && !msg.isEmpty()) {
            messages.add(msg);
        }
        res.sendRedirect("chat.jsp");
    }
}

/* chat.jsp */
<%@ page import="java.util.List"%>
<%@ page import="xss.chat.ChatServlet"%>
<html>
<head><title>Chat</title></head>
<body>
    <h1>Chat Messages</h1>
    <% for (String msg : ChatServlet.messages) { %>
        <div><%= msg %></div>
    <% } %>
    <form action="chat" method="post">
        <input type="text" name="message">
        <button type="submit">Send</button>
    </form>
</body>
</html>