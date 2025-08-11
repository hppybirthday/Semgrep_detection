import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/files")
public class FileDownloadController {

    private static final String BASE_PATH = "/var/www/files/";
    private static final Logger logger = Logger.getLogger(FileDownloadController.class.getName());

    @GetMapping("/{filename}")
    public ResponseEntity<String> downloadFile(@PathVariable String filename) {
        if (!isValidFilename(filename)) {
            return ResponseEntity.status(400).body("Invalid file type");
        }

        String filePath = BASE_PATH + filename;
        File file = new File(filePath);

        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            logger.info("File accessed: " + filename);
            return ResponseEntity.ok(content.toString());
        } catch (IOException e) {
            logger.severe("Error reading file: " + e.getMessage());
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam String filename, @RequestBody String content) {
        String filePath = BASE_PATH + filename;
        File file = new File(filePath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
            return ResponseEntity.ok("File uploaded");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }

    private boolean isValidFilename(String filename) {
        return filename.endsWith(".txt") && !filename.contains("..");
    }

    private boolean isAllowedPath(String path) {
        return Paths.get(BASE_PATH).normalize().startsWith(Paths.get(path).normalize());
    }
}