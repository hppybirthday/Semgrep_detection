import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 聊天文件下载服务（存在路径遍历漏洞）
 */
public class ChatFileDownload extends HttpServlet {
    private static final String BASE_DIR = "/var/chat_uploads/";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        String fileParam = req.getParameter("file");
        if (fileParam == null || fileParam.isEmpty()) {
            res.sendError(400, "Missing file parameter");
            return;
        }

        try {
            // 漏洞点：直接拼接用户输入构造文件路径
            File file = new File(BASE_DIR + fileParam);
            if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
                res.sendError(403, "Invalid file path");
                return;
            }

            if (!file.exists()) {
                res.sendError(404, "File not found");
                return;
            }

            res.setContentType("application/octet-stream");
            res.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");

            try (FileInputStream fis = new FileInputStream(file);
                 ServletOutputStream sos = res.getOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    sos.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            res.sendError(500, "Internal server error: " + e.getMessage());
        }
    }

    // 用于生成测试文件的main方法
    public static void main(String[] args) throws Exception {
        File testDir = new File(BASE_DIR);
        if (!testDir.exists()) testDir.mkdirs();
        
        File testFile = new File(BASE_DIR + "test.txt");
        try (FileWriter writer = new FileWriter(testFile)) {
            writer.write("Chat message archive");
        }
    }
}