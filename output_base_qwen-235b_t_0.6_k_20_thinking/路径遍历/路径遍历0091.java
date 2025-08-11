import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1")
public class BankFileService {

    private static final String BASE_DIR = "/opt/bank_data/customer_documents/";

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadDocument(@RequestParam("filename") String filename) throws IOException {
        // 漏洞点：未校验用户输入
        File file = new File(BASE_DIR + filename);
        
        if (!file.exists()) {
            throw new RuntimeException("File not found");
        }
        
        Path path = Paths.get(file.getAbsolutePath());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", filename);
        
        return ResponseEntity.ok()
                .headers(headers)
                .body(Files.readAllBytes(path));
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadDocument(@RequestParam("filename") String filename, @RequestBody byte[] content) throws IOException {
        File file = new File(BASE_DIR + filename);
        Files.write(file.toPath(), content);
        return ResponseEntity.ok("Upload successful");
    }

    public static void main(String[] args) {
        SpringApplication.run(BankFileService.class, args);
    }
}