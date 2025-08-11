package com.example.filemanager.controller;

import com.example.filemanager.domain.FileEntity;
import com.example.filemanager.domain.FileRepository;
import com.example.filemanager.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Controller
@RequestMapping("/files")
public class FileController {
    
    @Autowired
    private FileService fileService;
    
    @Autowired
    private FileRepository fileRepository;
    
    @GetMapping
    public String listFiles(Model model) {
        List<FileEntity> files = fileRepository.findAll();
        model.addAttribute("files", files);
        return "file-list";
    }
    
    @PostMapping
    public String uploadFile(@RequestParam("file") MultipartFile file) {
        FileEntity savedFile = fileService.saveFile(file);
        return "redirect:/files";
    }
}

package com.example.filemanager.domain;

import javax.persistence.*;

@Entity
public class FileEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    private String content;
    
    // Getters and setters
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getContent() {
        return content;
    }
    
    public void setContent(String content) {
        this.content = content;
    }
}

package com.example.filemanager.service;

import com.example.filemanager.domain.FileEntity;
import com.example.filemanager.domain.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
public class FileService {
    
    @Autowired
    private FileRepository fileRepository;
    
    public FileEntity saveFile(MultipartFile file) throws IOException {
        FileEntity entity = new FileEntity();
        entity.setName(file.getOriginalFilename()); // Vulnerable point
        entity.setContent(new String(file.getBytes()));
        return fileRepository.save(entity);
    }
}

// Thymeleaf template (file-list.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>File List</title>
</head>
<body>
    <h1>File List</h1>
    <table>
        <tr th:each="file : ${files}">
            <td th:text="${file.name}">Filename</td> <!-- Vulnerable rendering -->
        </tr>
    </table>
    
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
</body>
</html>
*/