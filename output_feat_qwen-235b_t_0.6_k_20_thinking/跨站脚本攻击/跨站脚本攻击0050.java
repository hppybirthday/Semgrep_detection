import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatServlet extends HttpServlet {
    private static List<String> messages = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        String message = req.getParameter("message");
        if (message != null && !message.isEmpty()) {
            messages.add(message);
        }
        res.sendRedirect("/chat");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        
        out.println("<html><body>");
        out.println("<h2>Chat Messages</h2>");
        out.println("<div style='border:1px solid #ccc;padding:10px;'>");
        
        for (String msg : messages) {
            // 漏洞点：直接将用户输入写入HTML内容
            out.println("<div style='margin:5px 0;'>" + msg + "</div>");
        }
        
        out.println("</div>");
        out.println("<form method='post'>");
        out.println("<input type='text' name='message' placeholder='Type your message'>");
        out.println("<input type='submit' value='Send'>");
        out.println("</form></body></html>");
    }
}

/*
部署描述符示例（web.xml）：
<servlet>
    <servlet-name>ChatServlet</servlet-name>
    <servlet-class>ChatServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>ChatServlet</servlet-name>
    <url-pattern>/chat</url-pattern>
</servlet-mapping>
*/