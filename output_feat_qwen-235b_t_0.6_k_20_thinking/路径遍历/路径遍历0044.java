import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * CRM系统文件上传处理接口（存在路径遍历漏洞）
 */
public class CRMFileUploadServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/crm_uploads/";
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(".pdf", ".docx", ".xlsx");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String bizPath = request.getParameter("bizPath");
        String basePath = request.getParameter("basePath");
        String chunkIndex = request.getParameter("chunkIndex");
        
        if (bizPath == null || basePath == null || chunkIndex == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }

        try {
            // 漏洞触发点：未正确验证路径参数
            Path targetPath = FileUtil.getFilePath(BASE_DIR, basePath, bizPath);
            
            if (!Files.exists(targetPath)) {
                Files.createDirectories(targetPath);
            }

            Part filePart = request.getPart("file");
            if (filePart == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No file uploaded");
                return;
            }

            String fileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
            if (!isAllowedExtension(fileName)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "File type not allowed");
                return;
            }

            Path tempFile = Files.createTempFile(targetPath, "chunk_", ".tmp");
            try (InputStream in = filePart.getInputStream();
                 OutputStream out = new FileOutputStream(tempFile.toFile())) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // 模拟分片合并操作
            if ("0".equals(chunkIndex)) {
                Path finalPath = targetPath.resolve("../merged_file" + fileName);
                GenerateUtil.generateFile(tempFile, finalPath);
                // 漏洞利用点：攻击者可构造路径删除任意文件
                GenerateUtil.deleteFile(tempFile);
            }

            response.getWriter().write("{\\"status\\":\\"success\\"}");
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private boolean isAllowedExtension(String fileName) {
        String ext = fileName.substring(fileName.lastIndexOf("."));
        return ALLOWED_EXTENSIONS.contains(ext);
    }
}

/**
 * 文件操作工具类（存在路径遍历漏洞）
 */
final class FileUtil {
    // 漏洞设计点：路径拼接未进行规范化处理
    public static Path getFilePath(String baseDir, String basePath, String bizPath) {
        // 漏洞触发链：用户输入直接拼接路径
        String combinedPath = baseDir + basePath + "/" + bizPath;
        // 错误的防御：仅检查是否存在../但未处理多次出现的情况
        if (combinedPath.contains("..")) {
            combinedPath = combinedPath.replace("..", "");
        }
        return Paths.get(combinedPath).normalize();
    }
}

/**
 * 文件生成工具类（漏洞危害扩展）
 */
final class GenerateUtil {
    public static void generateFile(Path source, Path target) throws IOException {
        // 漏洞危害体现：使用不安全的路径进行文件操作
        Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }

    public static void deleteFile(Path filePath) throws IOException {
        // 漏洞利用形态：删除任意系统文件
        if (Files.exists(filePath)) {
            Files.delete(filePath);
        }
    }
}