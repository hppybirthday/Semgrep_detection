import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class FileServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(FileServiceApplication.class, args);
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
        try {
            Class<?> fileUtilClass = Class.forName("com.example.FileUtil");
            Method validateMethod = fileUtilClass.getMethod("validateFilename", String.class);
            boolean isValid = (boolean) validateMethod.invoke(null, filename);
            
            if (!isValid) {
                throw new IllegalArgumentException("Invalid filename");
            }

            String basePath = "/var/www/files/";
            String filePath = basePath + filename;
            File file = new File(filePath);
            
            if (!file.exists()) {
                throw new RuntimeException("File not found");
            }

            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            return ResponseEntity.ok().body(data);
        } catch (Exception e) {
            throw new IOException("File operation failed: " + e.getMessage());
        }
    }
}

class FileUtil {
    public static boolean validateFilename(String filename) {
        // 模拟动态验证逻辑
        return filename != null && filename.matches("[a-zA-Z0-9_\\-\\.]+");
    }
}