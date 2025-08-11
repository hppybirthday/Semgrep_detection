import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatServlet extends HttpServlet {
    static List<Message> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            String user = req.getParameter("user");
            String msg = req.getParameter("msg");
            messages.add(new Message(user, msg));
            res.sendRedirect("chat.jsp");
        } catch (Exception e) {}
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setAttribute("messages", messages);
            req.getRequestDispatcher("chat.jsp").forward(req, res);
        } catch (Exception e) {}
    }
}

class Message {
    String user, content;
    Message(String u, String c) {
        user = u; content = c;
    }
}

// chat.jsp
<%@ page import="java.util.*,ChatServlet.Message" %>
<% List<Message> msgs = (List<Message>)request.getAttribute("messages"); %>
<html><body>
<h2>Chat Room</h2>
<table>
<% for (Message m : msgs) { %>
  <tr><td><b><%= m.user %>:</b> <%= m.content %></td></tr>
<% } %>
</table>
<form action="ChatServlet" method="post">
User: <input name="user"> Message: <input name="msg">
<input type="submit" value="Send">
</form>
</body></html>