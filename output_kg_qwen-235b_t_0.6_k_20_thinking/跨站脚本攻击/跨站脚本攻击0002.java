package com.example.chat;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/chat")
public class ChatServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static List<String> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String message = request.getParameter("message");
        if (message != null && !message.trim().isEmpty()) {
            messages.add(message);
        }
        
        response.sendRedirect("chat");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Chat App</title></head><body>");
        html.append("<h2>Chat Messages:</h2>");
        html.append("<div id='chat-box'>");
        
        messages.forEach(msg -> html.append("<div class='message'>").append(msg).append("</div>"));
        
        html.append("</div>");
        html.append("<form action='chat' method='post'>");
        html.append("<input type='text' name='message' placeholder='Type your message...'>");
        html.append("<button type='submit'>Send</button>");
        html.append("</form></body></html>");
        
        out.println(html.toString());
    }
}