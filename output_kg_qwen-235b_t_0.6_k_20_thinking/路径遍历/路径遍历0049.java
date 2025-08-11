import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 聊天应用用户头像上传服务
 * 存在路径遍历漏洞
 */
public class AvatarUploadServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "/var/www/chat_app/uploads/";
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String avatarData = request.getParameter("avatar");
        
        if (username == null || avatarData == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }
        
        // 漏洞点：直接拼接用户输入构造文件路径
        String filePath = UPLOAD_DIR + username + "/avatar.jpg";
        
        // 检查父目录是否存在
        File userDir = new File(UPLOAD_DIR + username);
        if (!userDir.exists()) {
            userDir.mkdirs();
        }
        
        // 写入文件
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(avatarData.getBytes());
            response.getWriter().write("Avatar uploaded successfully");
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Upload failed");
        }
    }
    
    @Override
    public void init() throws ServletException {
        // 确保上传目录存在
        File uploadDir = new File(UPLOAD_DIR);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }
    }
    
    // 模拟文件读取功能（漏洞利用点）
    public String readLogFile(String filename) throws IOException {
        StringBuilder content = new StringBuilder();
        // 漏洞点：未校验文件名中的../
        File file = new File("/var/www/chat_app/logs/" + filename);
        
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
    
    // 模拟的管理接口（危险功能）
    public void deleteFile(String filepath) {
        File file = new File("/var/www/chat_app/" + filepath);
        if (file.exists()) {
            file.delete(); // 漏洞点：允许删除任意路径文件
        }
    }
}