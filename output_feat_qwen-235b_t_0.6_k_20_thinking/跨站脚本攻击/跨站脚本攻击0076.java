package com.crm.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/files")
public class FileUploadController {
    private List<String> uploadedFiles = new ArrayList<>();

    @GetMapping
    public String listFiles(Model model) {
        model.addAttribute("files", uploadedFiles);
        return "fileList";
    }

    @PostMapping
    public String handleFileUpload(@RequestParam("file") MultipartFile file, Model model) {
        if (file.isEmpty()) {
            model.addAttribute("error", "No file selected");
            return "fileList";
        }
        
        // Vulnerable: Directly using original filename without sanitization
        String filename = file.getOriginalFilename();
        uploadedFiles.add(filename);
        
        // Simulate success message with unsanitized input
        model.addAttribute("success", "File '" + filename + "' uploaded successfully");
        return "fileList";
    }
}

// Thymeleaf template (fileList.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>CRM File List</title>
</head>
<body>
    <h1>Uploaded Files</h1>
    
    <div th:if="${success}">
        <p th:text="${success}"></p> <!-- XSS Vulnerability here -->
    </div>
    
    <div th:if="${error}">
        <p th:text="${error}"></p> <!-- XSS Vulnerability here -->
    </div>
    
    <ul>
        <li th:each="file : ${files}"
            th:text="${file}"> <!-- XSS Vulnerability here -->
        </li>
    </ul>
    
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" />
        <button type="submit">Upload</button>
    </form>
</body>
</html>
*/