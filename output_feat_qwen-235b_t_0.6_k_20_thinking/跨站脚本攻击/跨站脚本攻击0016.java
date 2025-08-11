import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptorServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String action = request.getParameter("action");
        String fileName = request.getParameter("filename");
        String content = request.getParameter("content");
        
        out.println("<html><body>");
        out.println("<h1>File Encryptor</h1>");
        
        if("encrypt".equals(action)) {
            // 模拟加密操作
            String encrypted = Base64.getEncoder().encodeToString(content.getBytes());
            // 漏洞点：直接拼接用户输入到HTML输出
            out.println("<div class='result'>");
            out.println("<h3>Encrypted File: " + fileName + "</h3>");
            out.println("<textarea rows='10' cols='50'>" + encrypted + "</textarea>");
            out.println("</div>");
        }
        else if("decrypt".equals(action)) {
            try {
                String decrypted = new String(Base64.getDecoder().decode(content));
                out.println("<div class='result'>");
                out.println("<h3>Decrypted Content:</h3>");
                // 漏洞点：直接输出用户输入内容
                out.println("<pre>" + decrypted + "</pre>");
                out.println("</div>");
            } catch (Exception e) {
                // 漏洞点：直接显示原始输入内容
                out.println("<div class='error'>Invalid encrypted content: " + content + "</div>");
            }
        }
        
        out.println("<a href='encryptor.html'>Back to tool</a>");
        out.println("</body></html>");
    }
}

// 前端HTML表单
/*
<!DOCTYPE html>
<html>
<head>
    <title>File Encryptor</title>
</head>
<body>
    <form action="FileEncryptorServlet" method="post">
        <input type="radio" name="action" value="encrypt" checked> Encrypt
        <input type="radio" name="action" value="decrypt"> Decrypt<br>
        Filename: <input type="text" name="filename"><br>
        Content:<br>
        <textarea name="content" rows="10" cols="50"></textarea><br>
        <input type="submit" value="Process">
    </form>
</body>
</html>
*/