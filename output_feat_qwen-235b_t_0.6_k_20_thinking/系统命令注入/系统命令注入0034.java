import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatBackupServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String dbUser = request.getParameter("dbUser");
        String dbPass = request.getParameter("dbPass");
        String dbName = request.getParameter("dbName");
        String backupPath = request.getParameter("backupPath");
        
        // 模拟防御式编程中的错误实践
        if (dbName == null || dbName.isEmpty() || 
            backupPath == null || backupPath.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }
        
        // 错误的过滤逻辑（仅过滤分号）
        if (dbName.contains(";")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid database name");
            return;
        }
        
        try {
            // 存在漏洞的命令拼接
            String command = String.format(
                "mysqldump -u%s -p%s --set-charset=utf8 %s | gzip > %s",
                dbUser, dbPass, dbName, backupPath);
            
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                response.getWriter().write("Backup successful");
            } else {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Backup failed");
            }
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server error");
            e.printStackTrace();
        }
    }
}

// 模拟聊天应用主类
public class ChatApplication {
    public static void main(String[] args) {
        System.out.println("Chat Application Started...");
        // 实际运行时会部署ChatBackupServlet处理备份请求
    }
}