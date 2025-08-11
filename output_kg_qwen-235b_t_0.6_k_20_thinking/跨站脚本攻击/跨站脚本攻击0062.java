package com.example.xsschat;

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
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setAttribute("messages", messages);
        req.getRequestDispatcher("/chat.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String message = req.getParameter("message");
        messages.add(message);
        resp.sendRedirect("chat");
    }
}

// chat.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="java.util.List" %>
<html>
<head><title>Chat</title></head>
<body>
    <h1>Chat Messages</h1>
    <div id="chat">
        <% List<String> messages = (List<String>) request.getAttribute("messages"); %>
        <% if (messages != null) { %>
            <% for (String msg : messages) { %>
                <div class="message"><%= msg %></div>
            <% } %>
        <% } %>
    </div>
    <form method="post">
        <input type="text" name="message" required>
        <button type="submit">Send</button>
    </form>
</body>
</html>