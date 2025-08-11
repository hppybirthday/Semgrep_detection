import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class TaskFilter implements Filter {
    public void init(FilterConfig filterConfig) {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String action = httpRequest.getParameter("action");
        if ("backupDB".equals(action)) {
            String db = httpRequest.getParameter("db");
            String user = httpRequest.getParameter("user");
            String password = httpRequest.getParameter("password");
            
            // 使用元编程风格动态构造命令
            String commandTemplate = "mysqldump -u%s -p%s --set-charset=utf8 %s > /backups/%s.sql";
            String timestamp = new Date().getTime() + "";
            String finalCommand = String.format(commandTemplate, 
                user, password, db, timestamp);
            
            try {
                // 存在漏洞的命令执行
                Process process = Runtime.getRuntime().exec(finalCommand);
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    httpResponse.getWriter().write("Backup success");
                } else {
                    httpResponse.getWriter().write("Backup failed");
                }
            } catch (Exception e) {
                e.printStackTrace();
                httpResponse.sendError(500);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {}
}