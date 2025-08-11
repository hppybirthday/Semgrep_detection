import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    
    // 模拟受限目录配置
    private static final String BASE_UPLOAD_DIR = "/var/www/chat_uploads";
    
    @PostMapping
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") byte[] fileData,
                                                            @RequestParam("categoryLink") String categoryLink) {
        try {
            // 漏洞点：直接拼接用户输入的categoryLink
            Path targetPath = Paths.get(BASE_UPLOAD_DIR + File.separator + categoryLink);
            
            // 检查父目录是否存在（错误地使用isDirectory检查自身）
            if (Files.exists(targetPath.getParent()) && !Files.isDirectory(targetPath.getParent())) {
                return ResponseEntity.badRequest().body("Invalid directory structure");
            }
            
            // 创建目录结构（存在漏洞：可能创建任意路径）
            if (!Files.exists(targetPath)) {
                Files.createDirectories(targetPath);
            }
            
            // 模拟文件保存（实际应使用安全文件名）
            Path finalPath = targetPath.resolve("uploaded_file.dat");
            Files.write(finalPath, fileData);
            
            return ResponseEntity.ok("File uploaded to: " + finalPath.toString());
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }

    // 模拟启动类
    public static void main(String[] args) {
        // 实际应由Spring Boot管理
        System.out.println("Starting insecure file upload server...");
    }
}

/*
攻击示例：
POST /api/upload?categoryLink=../../../../etc/passwd HTTP/1.1
Content-Type: multipart/form-data; boundary=----

------
Content-Disposition: form-data; name="file"; filename="evil.dat"

恶意内容
------
*/