import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class ChatServlet extends HttpServlet {
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
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body><h2>Chat Room</h2>");
        out.println("<div style='border:1px solid #ccc; padding:10px; height:300px; overflow:auto;'>");
        
        for (String msg : messages) {
            out.println("<div>" + msg + "</div>");
        }
        
        out.println("</div>");
        out.println("<form method='post'>");
        out.println("<input type='text' name='message' style='width:80%' required>");
        out.println("<input type='submit' value='Send'>");
        out.println("</form></body></html>");
    }
}