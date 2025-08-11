import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptor extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String action = request.getParameter("action");
        String key = request.getParameter("key");
        String content = request.getParameter("content");
        
        out.println("<html><body>");
        out.println("<h2>文件加密解密工具</h2>");
        out.println("<form method='get'>");
        out.println("操作: <select name='action'>");
        out.println("  <option value='encrypt'" + ("encrypt".equals(action) ? " selected" : "") + ">加密</option>");
        out.println("  <option value='decrypt'" + ("decrypt".equals(action) ? " selected" : "") + ">解密</option>");
        out.println("</select><br>");
        out.println("密钥: <input type='text' name='key' value='" + (key != null ? key : "") + "'><br>");
        out.println("内容: <textarea name='content'>" + (content != null ? content : "") + "</textarea><br>");
        out.println("<input type='submit' value='提交'>");
        out.println("</form>");
        
        if ("encrypt".equals(action)) {
            if (key == null || key.isEmpty()) {
                out.println("<p style='color:red'>错误：密钥不能为空！当前输入：" + key + "</p>");
            } else {
                out.println("<p>加密成功！密钥长度：" + key.length() + "</p>");
            }
        } else if ("decrypt".equals(action)) {
            if (key == null || key.isEmpty()) {
                out.println("<script>alert('请提供有效密钥');</script>");
                out.println("<p style='color:red'>解密失败：密钥无效！输入内容：" + content + "</p>");
            } else {
                out.println("<p>解密成功！密钥哈希：" + key.hashCode() + "</p>");
            }
        }
        
        out.println("<p>示例攻击载荷：<br>");
        out.println("加密攻击: <input type='text' value=\\"test\\" onfocus=\\"alert(document.cookie)\\" style='width:300px;'>");
        out.println("</body></html>");
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>FileEncryptor</servlet-name>
    <servlet-class>FileEncryptor</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>FileEncryptor</servlet-name>
    <url-pattern>/crypto</url-pattern>
</servlet-mapping>
*/