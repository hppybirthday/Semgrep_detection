import org.springframework.web.bind.annotation.*;
import java.io.*;
import org.springframework.util.FileCopyUtils;

@RestController
public class FileUploadController {
    @PostMapping("/upload")
    public String uploadFile(@RequestParam String path, @RequestParam String content) {
        try {
            String baseDir = System.getenv("STORAGE_DIR");
            if (baseDir == null) baseDir = "/var/storage";
            File file = new File(String.format("%s/%s/debug.log", baseDir, path));
            
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }
            
            FileCopyUtils.copy(content.getBytes(), file);
            return "OK";
        } catch (Exception e) {
            return "Error";
        }
    }
    
    public static void main(String[] args) {
        // 模拟Spring Boot启动
    }
}
// 编译依赖：spring-boot-starter-web, spring-core