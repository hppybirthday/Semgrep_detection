import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerablePingServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        try {
            String host = request.getParameter("host");
            
            // 防御式编程尝试：过滤特殊字符（存在缺陷的过滤）
            if (host != null && host.matches("[a-zA-Z0-9.\\-]+")) {
                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ping -c 4 " + host);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                out.println("<pre>" + "Ping结果:\
");
                while ((line = reader.readLine()) != null) {
                    out.println(line);
                }
                out.println("</pre>");
            } else {
                out.println("无效的主机名输入");
            }
        } catch (Exception e) {
            out.println("发生错误：" + e.getMessage());
            e.printStackTrace(out);
        } finally {
            out.close();
        }
    }

    public void init() throws ServletException {
        // 初始化代码（如果需要）
    }

    public void destroy() {
        // 清理代码（如果需要）
    }
}