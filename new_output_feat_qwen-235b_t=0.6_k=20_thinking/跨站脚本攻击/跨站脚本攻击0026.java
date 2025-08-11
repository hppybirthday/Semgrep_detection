package com.crm.filemanager.controller;

import com.crm.filemanager.entity.FileEntity;
import com.crm.filemanager.service.FileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
public class FileUploadController {
    private final FileService fileService;

    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        String originalFilename = file.getOriginalFilename();
        
        // 错误地认为preProcessFilename已处理安全问题
        String processedName = preProcessFilename(originalFilename);
        
        // 将用户控制的文件名直接存储
        fileService.saveFile(processedName);
        
        return ResponseEntity.ok("File uploaded: " + processedName);
    }

    @GetMapping("/list")
    public List<FileEntity> listFiles() {
        return fileService.getAllFiles();
    }

    /**
     * 误认为此方法可防止XSS（实际未进行HTML转义）
     */
    private String preProcessFilename(String filename) {
        // 仅替换部分标签但存在绕过可能
        return filename.replace("<script>", "").replace("</script>", "");
    }
}

package com.crm.filemanager.service;

import com.crm.filemanager.entity.FileEntity;
import com.crm.filemanager.repository.FileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FileService {
    private final FileRepository fileRepository;

    public void saveFile(String filename) {
        // 直接存储用户输入的文件名到数据库
        fileRepository.save(new FileEntity(filename));
    }

    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }
}

package com.crm.filemanager.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class FileEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String filename;

    public FileEntity() {}

    public FileEntity(String filename) {
        this.filename = filename;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
}

package com.crm.filemanager.repository;

import com.crm.filemanager.entity.FileEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FileRepository extends JpaRepository<FileEntity, Long> {}
