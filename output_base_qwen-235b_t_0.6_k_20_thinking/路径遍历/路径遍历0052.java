import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.function.Function;

@SpringBootApplication
@RestController
public class FileServer {

    // 模拟开发者错误地认为基础路径可以限制访问范围
    private static final String BASE_DIR = "/var/www/files/";

    public static void main(String[] args) {
        SpringApplication.run(FileServer.class, args);
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) {
        try {
            // 路径拼接函数式写法（错误示范）
            Function<String, String> buildPath = (name) -> BASE_DIR + name;
            String filePath = buildPath.apply(filename);

            // 漏洞触发点：直接使用未经校验的路径
            File file = new File(filePath);
            byte[] content = Files.readAllBytes(file.toPath());

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(content);
        } catch (IOException e) {
            return ResponseEntity.status(404).body("File not found".getBytes());
        }
    }

    // 模拟前端渲染的文件列表（增强真实感）
    @GetMapping("/list")
    public String listFiles() {
        return "<ul>\
<li><a href='?filename=report.pdf'>report.pdf</a></li>\
<li><a href='?filename=notes.txt'>notes.txt</a></li>\
</ul>";
    }
}