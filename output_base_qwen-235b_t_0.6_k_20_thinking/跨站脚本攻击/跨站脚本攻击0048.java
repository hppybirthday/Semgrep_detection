import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.util.Base64;

public class VulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<form method='post'>");
        out.println("文件名：<input type='text' name='fileName'><br>");
        out.println("<input type='radio' name='action' value='encrypt' checked>加密");
        out.println("<input type='radio' name='action' value='decrypt'>解密<br>");
        out.println("<input type='submit' value='处理'>");
        out.println("</form>");
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String fileName = req.getParameter("fileName");
        String action = req.getParameter("action");
        String output = "";
        if("encrypt".equals(action)) {
            output = encrypt(fileName);
        } else if("decrypt".equals(action)) {
            output = decrypt(fileName);
        } else {
            output = "无效操作";
        }
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h3>结果: " + output + "</h3>");
        out.println("<p>文件名: " + fileName + "</p>");
        out.println("</body></html>");
    }

    private String encrypt(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    private String decrypt(String data) {
        try {
            return new String(Base64.getDecoder().decode(data));
        } catch (Exception e) {
            return "解密失败";
        }
    }
}