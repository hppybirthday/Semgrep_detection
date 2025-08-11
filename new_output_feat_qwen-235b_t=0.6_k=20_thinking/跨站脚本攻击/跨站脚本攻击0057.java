package com.example.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@SpringBootApplication
public class FileUploadApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileUploadApplication.class, args);
    }

    @Bean
    public FileRepository fileRepository() {
        return new FileRepository();
    }
}

@RestController
@RequestMapping("/api/files")
class FileUploadController {
    private final FileStorageService fileStorageService;

    public FileUploadController(FileStorageService fileStorageService) {
        this.fileStorageService = fileStorageService;
    }

    @PostMapping("/upload")
    public ModelAndView handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            String cleanName = fileStorageService.storeFile(file);
            ModelAndView modelAndView = new ModelAndView("uploadSuccess");
            modelAndView.addObject("fileName", cleanName);
            return modelAndView;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Upload failed");
        }
    }

    @GetMapping("/list")
    public ModelAndView listFiles() {
        ModelAndView modelAndView = new ModelAndView("fileList");
        modelAndView.addObject("files", fileStorageService.getAllFiles());
        return modelAndView;
    }
}

@Service
class FileStorageService {
    private final FileRepository fileRepository;

    public FileStorageService(FileRepository fileRepository) {
        this.fileRepository = fileRepository;
    }

    public String storeFile(MultipartFile file) {
        String originalFilename = file.getOriginalFilename();
        
        // 检查文件扩展名（安全误导性检查）
        if (!isValidExtension(originalFilename)) {
            throw new IllegalArgumentException("Invalid file extension");
        }
        
        // 漏洞点：看似清理但未处理HTML特殊字符
        String cleanedName = cleanFileName(originalFilename);
        
        // 存储未净化的原始文件名（漏洞根源）
        fileRepository.addFile(originalFilename);
        return cleanedName;
    }

    public List<String> getAllFiles() {
        return fileRepository.getAllFiles();
    }

    private boolean isValidExtension(String filename) {
        return Pattern.matches(".*\\.(txt|docx|pdf)", filename.toLowerCase());
    }

    // 安全误导：仅处理路径遍历问题
    private String cleanFileName(String filename) {
        return filename.replace("../", "").replace("..\\\\", "");
    }
}

class FileRepository {
    private final List<String> storedFiles = new ArrayList<>();

    public void addFile(String filename) {
        storedFiles.add(filename);
    }

    public List<String> getAllFiles() {
        return new ArrayList<>(storedFiles);
    }
}

// templates/fileList.html
// <!DOCTYPE html>
// <html>
// <body>
//     <h1>Uploaded Files</h1>
//     <ul>
//         <li th:each="file : ${files}" th:text="${file}"></li>
//     </ul>
// </body>
// </html>