import java.io.IOException;
import java.nio.file.*;
import java.util.function.Function;

/**
 * CRM系统中的客户文档服务
 * 存在路径遍历漏洞的示例代码
 */
public class CustomerDocumentService {
    // 基础目录（模拟受限目录）
    private static final Path BASE_DIR = Paths.get("/var/crm/documents").toAbsolutePath();

    // 使用函数式接口处理文件下载
    private final Function<String, String> documentDownloader = filename -> {
        try {
            // 漏洞点：直接拼接用户输入
            Path targetPath = BASE_DIR.resolve(filename).normalize();
            
            // 检查是否超出基础目录（本应正确执行，但存在绕过可能）
            if (!targetPath.startsWith(BASE_DIR)) {
                return "Access Denied: Attempted path traversal";
            }

            // 读取文件内容（存在漏洞）
            return new String(Files.readAllBytes(targetPath));
        } catch (IOException e) {
            return "Error reading file: " + e.getMessage();
        }
    };

    // 模拟API端点处理
    public String handleDownloadRequest(String filename) {
        System.out.println("[INFO] Download request for: " + filename);
        return documentDownloader.apply(filename);
    }

    // 测试用的main方法
    public static void main(String[] args) {
        CustomerDocumentService service = new CustomerDocumentService();
        
        // 创建测试文件
        createTestFile(BASE_DIR.resolve("test.txt"), "This is a test document");
        
        // 正常访问
        System.out.println("Normal access:");
        System.out.println(service.handleDownloadRequest("test.txt"));
        
        // 漏洞利用示例
        System.out.println("\
Path traversal attempt:");
        System.out.println(service.handleDownloadRequest("../../../../etc/passwd"));
    }

    // 创建测试文件的辅助方法
    private static void createTestFile(Path path, String content) {
        try {
            // 确保目录存在
            Files.createDirectories(path.getParent());
            // 如果文件不存在则创建
            if (!Files.exists(path)) {
                Files.write(path, content.getBytes());
            }
        } catch (IOException e) {
            System.err.println("Error creating test file: " + e.getMessage());
        }
    }
}