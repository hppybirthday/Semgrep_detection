package com.example.xss;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/guestbook")
public class GuestbookServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<String> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String message = request.getParameter("message");
        if (message != null && !message.trim().isEmpty()) {
            messages.add(message);
        }
        doGet(request, response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        out.println("<html><head><title>Guestbook</title></head><body>");
        out.println("<h2>Sign our guestbook:</h2>");
        out.println("<form method='post'>");
        out.println("Message: <input type='text' name='message' size='50'>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form><hr><h3>Messages:</h3>");
        
        if (messages.isEmpty()) {
            out.println("<p>No messages yet.</p>");
        } else {
            out.println("<ul>");
            for (String msg : messages) {
                out.println("<li>" + msg + "</li>"); // Vulnerable line
            }
            out.println("</ul>");
        }
        
        out.println("</body></html>");
    }
}