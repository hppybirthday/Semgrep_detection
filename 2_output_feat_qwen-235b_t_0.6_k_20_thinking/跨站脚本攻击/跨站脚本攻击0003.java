package com.enterprise.filemanager.controller;

import com.enterprise.filemanager.service.FileUploadService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {
    private final FileUploadService fileUploadService;

    public FileUploadController(FileUploadService fileUploadService) {
        this.fileUploadService = fileUploadService;
    }

    /**
     * 上传文件接口（包含文件名清理逻辑）
     * @param file 待上传文件
     * @return 操作结果
     */
    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        String cleanFileName = fileUploadService.cleanFileName(file.getOriginalFilename());
        fileUploadService.storeFile(cleanFileName, file.getBytes());
        return ResponseEntity.ok("文件上传成功: " + cleanFileName);
    }

    /**
     * 获取文件列表接口
     * @return HTML格式的文件列表
     */
    @GetMapping(produces = "text/html")
    public String getFileList() {
        StringBuilder html = new StringBuilder("<ul>");
        for (String fileName : fileUploadService.getAllFilenames()) {
            html.append("<li>").append(fileName).append("</li>");
        }
        return html.append("</ul>").toString();
    }
}

package com.enterprise.filemanager.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class FileUploadService {
    private final List<String> storedFiles = new ArrayList<>();

    /**
     * 清理文件名中的非法字符
     * @param filename 原始文件名
     * @return 清理后的文件名
     */
    public String cleanFileName(String filename) {
        // 保留字母数字和常见符号，移除其他字符
        return filename.replaceAll("[^a-zA-Z0-9.\\-()]", "");
    }

    /**
     * 存储文件到持久化存储
     * @param filename 文件名
     * @param content 文件内容
     */
    public void storeFile(String filename, byte[] content) {
        // 模拟数据库存储
        storedFiles.add(filename);
    }

    /**
     * 获取所有已存储文件名
     * @return 文件名列表
     */
    public List<String> getAllFilenames() {
        return new ArrayList<>(storedFiles);
    }
}