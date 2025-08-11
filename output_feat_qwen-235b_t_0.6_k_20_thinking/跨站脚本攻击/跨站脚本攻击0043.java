import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

// 消息模型类
class Message {
    private String content;
    public Message(String content) {
        this.content = content;
    }
    public String getContent() {
        return content;
    }
}

// 消息服务类
class MessageService {
    private List<Message> messages = new ArrayList<>();
    
    public void addMessage(String content) {
        messages.add(new Message(content));
    }
    
    public List<Message> getMessages() {
        return messages;
    }
}

// 主Servlet处理类
public class MessageServlet extends HttpServlet {
    private MessageService messageService = new MessageService();
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String message = request.getParameter("message");
        if(message != null && !message.isEmpty()) {
            messageService.addMessage(message);
        }
        response.sendRedirect("messages.jsp");
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("messages", messageService.getMessages());
        request.getRequestDispatcher("messages.jsp").forward(request, response);
    }
}

/* 
Web页面(messages.jsp)内容：
<%@ page import="java.util.List,Message" %>
<html>
<head><title>客户留言</title></head>
<body>
    <h2>客户留言板</h2>
    <form action="MessageServlet" method="POST">
        <textarea name="message"></textarea>
        <input type="submit" value="提交">
    </form>
    <hr>
    <% List<Message> messages = (List<Message>) request.getAttribute("messages"); %>
    <% if(messages != null) { %>
        <% for(Message msg : messages) { %>
            <div><%= msg.getContent() %></div>  <!-- 这里存在XSS漏洞 -->
        <% } %>
    <% } %>
</body>
</html>
*/