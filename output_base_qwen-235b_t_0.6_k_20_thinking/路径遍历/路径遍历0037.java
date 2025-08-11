import org.springframework.core.io.Resource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam String filename) {
        return fileService.downloadFile(filename);
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<String> handleIOException() {
        return ResponseEntity.status(500).body("File operation failed");
    }
}

@Service
class FileService {

    private static final String BASE_PATH = "/var/www/files/";

    public ResponseEntity<Resource> downloadFile(String filename) throws IOException {
        String filePath = BASE_PATH + filename; // \u8def\u5f84\u904d\u5386\u6f0f\u6d1e\u70b9
        File file = new File(filePath);

        if (!file.exists()) {
            throw new IOException("File not found");
        }

        Resource resource = new FileSystemResource(file);

        return ResponseEntity.ok()
                .header("Content-Type", "application/octet-stream")
                .header("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"")
                .body(resource);
    }
}