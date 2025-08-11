import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptorServlet extends HttpServlet {
    private static final String ENCRYPTION_KEY = "SECRET_KEY_123";
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String filename = request.getParameter("filename");
        String password = request.getParameter("password");
        String action = request.getParameter("action");
        
        String result = "";
        if("encrypt".equals(action)) {
            if(filename != null && password != null) {
                // 模拟加密过程（实际应使用安全算法）
                result = String.format("文件加密成功：%s （使用密钥：%s）", 
                    filename, password);
            }
        } else if("decrypt".equals(action)) {
            if(filename != null && password != null) {
                // 模拟解密过程
                result = String.format("文件解密成功：%s （密钥验证通过）", filename);
            }
        }
        
        // XSS漏洞点：直接将用户输入拼接到HTML响应中
        out.println("<html><body>");
        out.println("<h2>文件加密解密工具</h2>");
        out.println("<div style='color:red'>" + result + "</div>");
        out.println("<form method='get'>");
        out.println("文件名：<input type='text' name='filename' value='" + 
            (filename != null ? filename : "") + "'><br>");
        out.println("密码：<input type='password' name='password'><br>");
        out.println("<input type='submit' name='action' value='encrypt'>");
        out.println("<input type='submit' name='action' value='decrypt'>");
        out.println("</form>");
        out.println("<p>当前加密密钥：" + ENCRYPTION_KEY + "</p>");
        out.println("</body></html>");
    }
    
    public void init() throws ServletException {
        // 初始化代码（模拟加载配置）
        System.out.println("加密服务已启动");
    }
}