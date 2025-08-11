import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatServlet extends HttpServlet {
    private List<String> messages = new ArrayList<>();

    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            String msg = req.getParameter("message");
            messages.add(msg);
            req.setAttribute("messages", messages);
            req.getRequestDispatcher("chat.jsp").forward(req, res);
        } catch (Exception e) { e.printStackTrace(); }
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        req.setAttribute("messages", messages);
        try { req.getRequestDispatcher("chat.jsp").forward(req, res); }
        catch (Exception e) { e.printStackTrace(); }
    }
}

// chat.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html><body>
    <h2>Chat Room</h2>
    <form method="post">
        Message: <input type="text" name="message">
        <input type="submit" value="Send">
    </form>
    <c:forEach items="${messages}" var="msg">
        <div><b>User:</b> ${msg}</div>
    </c:forEach>
</body></html>