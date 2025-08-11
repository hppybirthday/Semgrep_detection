import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class VulnerableFileServer implements CommandLineRunner {
    private static final String BASE_DIR = "/var/www/files/";

    public static void main(String[] args) {
        SpringApplication.run(VulnerableFileServer.class, args);
    }

    @GetMapping("/api/files/{filename}")
    public String getFileContent(@PathVariable String filename) throws Exception {
        // 元编程特性：动态方法调用
        Method method = this.getClass().getMethod("readFile", String.class);
        return (String) method.invoke(this, filename);
    }

    private String readFile(String filename) throws IOException {
        // 漏洞点：未正确处理路径遍历字符
        if (filename.contains("../")) {
            filename = filename.replace("../", ""); // 简单替换容易被绕过
        }
        
        // 构造文件路径
        Path filePath = Paths.get(BASE_DIR + filename);
        
        // 检查文件是否存在
        if (!Files.exists(filePath)) {
            return "File not found";
        }
        
        // 读取文件内容
        byte[] fileBytes = Files.readAllBytes(filePath);
        return Base64.getEncoder().encodeToString(fileBytes);
    }

    // 启动时创建测试文件
    @Override
    public void run(String... args) throws Exception {
        Files.createDirectories(Paths.get(BASE_DIR));
        Files.write(Paths.get(BASE_DIR + "test.txt"), "SecureContent123".getBytes());
        
        // 创建敏感文件
        Files.write(Paths.get("/tmp/secret.conf"), "DB_PASSWORD=Admin@2023".getBytes());
    }
}