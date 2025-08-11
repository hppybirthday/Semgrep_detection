import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class FileEncryptorServlet extends HttpServlet {
    private List<String> history = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String filename = request.getParameter("filename");
        String content = request.getParameter("content");
        
        // 模拟加密过程（实际应使用安全算法）
        String encrypted = Base64.getEncoder().encodeToString(content.getBytes());
        
        // 存储到历史记录（未过滤用户输入）
        history.add("[加密] " + filename + ": " + encrypted);
        
        response.sendRedirect("history.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setAttribute("history", history);
        request.getRequestDispatcher("history.jsp").forward(request, response);
    }
}

// history.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>操作历史</title></head>
<body>
    <h2>加密操作历史：</h2>
    <ul>
    <% 
        List<String> history = (List<String>) request.getAttribute("history");
        if (history != null) {
            for (String record : history) {
    %>
        <li><%= record %></li>  <!-- 跨站脚本漏洞点 -->
    <%      }
        }
    %>
    </ul>
    <a href="javascript:alert(document.cookie)">测试XSS</a> <!-- 恶意示例 -->
</body>
</html>