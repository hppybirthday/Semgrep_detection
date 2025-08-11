import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;

public class CryptoServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        String fileName = request.getParameter("filename");
        String key = request.getParameter("key");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        if("encrypt".equals(action)) {
            String encrypted = Base64.getEncoder().encodeToString((key + fileName).getBytes());
            out.println("<html><body>");
            out.println("<h2>加密成功!</h2>");
            out.println("<p>加密文件名: " + fileName + "</p>");
            out.println("<p>加密结果: " + encrypted + "</p>");
            out.println("<button onclick=\\"location.href='?action=decrypt&result=" + encrypted + "&key=" + key + "'\\">解密</button>");
            out.println("</body></html>");
        }
        else if("decrypt".equals(action)) {
            String encryptedData = request.getParameter("result");
            try {
                String decrypted = new String(Base64.getDecoder().decode(encryptedData)).substring(key.length());
                out.println("<html><body>");
                out.println("<h2>解密成功!</h2>");
                out.println("<p>原始文件名: " + fileName + "</p>");
                out.println("<p>解密结果: " + decrypted + "</p>");
                out.println("</body></html>");
            } catch (Exception e) {
                out.println("解密失败: " + e.getMessage());
            }
        }
    }
    
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }
}