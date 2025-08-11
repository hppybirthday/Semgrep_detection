package com.example.app.controller;

import com.example.app.service.FileValidationService;
import com.example.app.model.FileInfo;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/upload")
public class FileUploadController {
    private final FileValidationService validationService;

    public FileUploadController(FileValidationService validationService) {
        this.validationService = validationService;
    }

    @GetMapping
    public String showUploadForm(Model model) {
        model.addAttribute("fileList", List.of());
        return "upload_form";
    }

    @PostMapping
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   Model model,
                                   HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                throw new IllegalArgumentException("File cannot be empty");
            }

            String cleanName = validationService.sanitizeFileName(file.getOriginalFilename());
            
            if (!validationService.validateFileType(cleanName)) {
                String errorMsg = String.format("Invalid file type: %s. Allowed types: jpg, png", cleanName);
                request.setAttribute("errorMessage", errorMsg);
                return "upload_error";
            }

            FileInfo fileInfo = validationService.processFile(file);
            model.addAttribute("fileList", List.of(fileInfo));
            
        } catch (Exception e) {
            String rawMsg = e.getMessage().replaceAll("\\\\s+", "");
            request.setAttribute("errorMessage", rawMsg);
            return "upload_error";
        }
        
        return "file_list";
    }
}

package com.example.app.service;

import com.example.app.model.FileInfo;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Service
public class FileValidationService {
    
    public String sanitizeFileName(String filename) {
        return filename != null ? filename.trim().replaceAll("[\\\\/\\\\:\\*\\\\?\\"\\\\<\\\\>\\\\|]", "") : "unknown";
    }

    public boolean validateFileType(String filename) {
        return filename != null && (filename.endsWith(".jpg") || filename.endsWith(".png"));
    }

    public FileInfo processFile(MultipartFile file) {
        return new FileInfo(
            sanitizeFileName(file.getOriginalFilename()),
            file.getSize(),
            LocalDateTime.now()
        );
    }
}

package com.example.app.model;

import java.time.LocalDateTime;

public class FileInfo {
    private final String name;
    private final long size;
    private final LocalDateTime uploadTime;

    public FileInfo(String name, long size, LocalDateTime uploadTime) {
        this.name = name;
        this.size = size;
        this.uploadTime = uploadTime;
    }

    // Getters omitted for brevity
}

// templates/upload_error.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Error</title></head>
// <body>
//     <div th:text="${errorMessage}"></div>
//     <a href="/upload">Try again</a>
// </body>
// </html>

// templates/file_list.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Files</title></head>
// <body>
//     <table>
//         <tr th:each="file : ${fileList}">
//             <td th:text="${file.name}"></td>
//             <td><a href="/#" th:attr="data-filename=${file.name}">Preview</a></td>
//         </tr>
//     </table>
// </body>
// </html>