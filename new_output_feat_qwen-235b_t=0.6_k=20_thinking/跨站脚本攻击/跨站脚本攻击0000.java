package com.securecryptool.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class SecureCryptoolApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecureCryptoolApplication.class, args);
    }
}

@Entity
class EncryptedFile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String filename;
    private String description; // XSS漏洞点
    private String encryptedContent;

    // Getters and setters
}

interface EncryptedFileRepository extends JpaRepository<EncryptedFile, Long> {
    List<EncryptedFile> findByFilenameContaining(String keyword);
}

@Service
class FileEncryptionService {
    String encryptContent(String content) {
        // 简化版加密逻辑
        return Base64.getEncoder().encodeToString(content.getBytes());
    }

    // 存在缺陷的输入过滤
    String sanitizeDescription(String input) {
        if (input == null) return "";
        return input.replaceAll("<(script|SCRIPT)>.*?</(script|SCRIPT)>", ""); // 仅过滤script标签
    }
}

@Controller
class FileController {
    private final EncryptedFileRepository fileRepo;
    private final FileEncryptionService encryptionService;

    public FileController(EncryptedFileRepository fileRepo, FileEncryptionService encryptionService) {
        this.fileRepo = fileRepo;
        this.encryptionService = encryptionService;
    }

    @GetMapping("/upload")
    String showUploadForm() {
        return "upload";
    }

    @PostMapping("/upload")
    String handleFileUpload(@RequestParam("file") MultipartFile file,
                           @RequestParam("description") String description,
                           Model model) {
        try {
            EncryptedFile encryptedFile = new EncryptedFile();
            encryptedFile.setFilename(file.getOriginalFilename());
            // 漏洞点：错误地认为sanitization足够安全
            encryptedFile.setDescription(encryptionService.sanitizeDescription(description));
            encryptedFile.setEncryptedContent(encryptionService.encryptContent(
                new String(file.getBytes())));

            fileRepo.save(encryptedFile);
            model.addAttribute("success", true);
        } catch (Exception e) {
            model.addAttribute("error", "Upload failed: " + e.getMessage());
        }
        return "upload";
    }

    @GetMapping("/files")
    String listFiles(@RequestParam(required = false) String keyword, Model model) {
        List<EncryptedFile> files = (keyword == null || keyword.isEmpty()) 
            ? fileRepo.findAll() 
            : fileRepo.findByFilenameContaining(keyword);
        model.addAttribute("files", files);
        return "fileList";
    }
}

// templates/upload.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.w3.org/1999/xhtml">
// <body>
//   <form method="post" action="/upload" enctype="multipart/form-data">
//     <input type="file" name="file" required/>
//     <input type="text" name="description" placeholder="文件描述"/>
//     <button type="submit">上传</button>
//   </form>
//   <div th:if="${success}">上传成功！</div>
//   <div th:if="${error}" th:text="${error}">错误信息</div>
// </body>
// </html>

// templates/fileList.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.w3.org/1999/xhtml">
// <body>
//   <table>
//     <tr th:each="file : ${files}">
//       <td th:text="${file.filename}">文件名</td>
//       <td th:utext="${file.description}">描述</td> <!-- 漏洞点：使用不安全的utext -->
//     </tr>
//   </table>
// </body>
// </html>