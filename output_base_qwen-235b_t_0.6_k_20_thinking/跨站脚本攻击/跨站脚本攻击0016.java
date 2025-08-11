import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/encrypt")
public class EncryptServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("fileName");
        String content = request.getParameter("content");
        
        // 模拟加密过程
        String encrypted = "ENCRYPTED_" + content;
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>文件: " + fileName + " 加密成功</h2>");
        out.println("<p>加密内容: " + encrypted + "</p>");
        out.println("<div>最近操作: 加密文件 <b>" + fileName + "</b> 已保存</div>");
        out.println("<script>document.write('上次操作用户: ' + document.cookie)</script>");
        out.println("</body></html>");
    }
}

// web.xml需配置servlet映射
// 漏洞示例请求: 
// http://localhost:8080/encrypt?fileName=<script>alert(1)</script>&content=test