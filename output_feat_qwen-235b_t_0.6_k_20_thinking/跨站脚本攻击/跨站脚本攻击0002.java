import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatServlet extends HttpServlet {
    private static List<String> messages = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            String msg = req.getParameter("message");
            messages.add(msg);
            res.sendRedirect("chat.jsp");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setAttribute("messages", messages);
            req.getRequestDispatcher("chat.jsp").forward(req, res);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// chat.jsp 内容：
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Chat</title></head>
<body>
    <form method="POST">
        <input type="text" name="message">
        <button type="submit">Send</button>
    </form>
    <div id="chat">
        ${messages.stream().map(m -> "<div>" + m + "</div>").reduce((a,b) -> a + b).orElse("")} // 漏洞点
    </div>
</body>
</html>