import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

@SpringBootApplication
public class MlXssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(MlXssDemoApplication.class, args);
    }
}

@Controller
class FileUploadController {
    private final List<String> uploadedFiles = new ArrayList<>();

    @GetMapping("/upload")
    public String showUploadForm(Model model) {
        model.addAttribute("files", uploadedFiles);
        return "upload";
    }

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, Model model) {
        if (file.isEmpty()) {
            model.addAttribute("error", "No file selected");
            return "upload";
        }

        String originalFilename = file.getOriginalFilename();
        
        // Vulnerable: Directly using user-controlled filename without sanitization
        uploadedFiles.add(originalFilename);
        
        // Simulate ML processing
        processFile(file, (data) -> {
            model.addAttribute("result", "Processed " + originalFilename + " with " + data);
        });

        return "upload";
    }

    private void processFile(MultipartFile file, Consumer<String> resultConsumer) {
        // Simulate ML model processing
        new Thread(() -> {
            try {
                Thread.sleep(100);
                resultConsumer.accept("200 features extracted");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }
}