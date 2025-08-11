package com.bank.portal.controller;

import com.bank.portal.model.FileMetadata;
import com.bank.portal.service.FileService;
import com.bank.portal.util.SanitizationUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Controller
@RequestMapping("/documents")
public class FileUploadController {
    private final FileService fileService;

    public FileUploadController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/list")
    public String listDocuments(Model model) {
        List<FileMetadata> files = fileService.getAllFiles();
        model.addAttribute("documents", files);
        return "document-list";
    }

    @PostMapping("/upload")
    public String uploadDocument(@RequestParam("file") MultipartFile file,
                                 @RequestParam("description") String description,
                                 Model model) {
        if (file.isEmpty()) {
            model.addAttribute("error", "Please select a file to upload");
            return "upload-form";
        }

        try {
            String originalFilename = file.getOriginalFilename();
            // 漏洞点：看似安全的文件名清理实际存在缺陷
            String sanitizedFilename = SanitizationUtil.cleanFileName(originalFilename);
            
            // 漏洞传播链：未正确验证清理结果
            FileMetadata metadata = new FileMetadata();
            metadata.setFileName(sanitizedFilename);
            metadata.setDescription(description);
            
            fileService.saveFile(metadata, file.getBytes());
            return "redirect:/documents/list";
        } catch (Exception e) {
            model.addAttribute("error", "Upload failed: " + e.getMessage());
            return "upload-form";
        }
    }
}

// 文件服务类
package com.bank.portal.service;

import com.bank.portal.model.FileMetadata;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class FileService {
    private final List<FileMetadata> fileStore = new ArrayList<>();

    public void saveFile(FileMetadata metadata, byte[] content) {
        // 存储逻辑（简化版）
        fileStore.add(metadata);
    }

    public List<FileMetadata> getAllFiles() {
        return new ArrayList<>(fileStore);
    }
}

// 数据模型
package com.bank.portal.model;

public class FileMetadata {
    private String fileName;
    private String description;

    // 漏洞传播点：未正确验证的getter方法
    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}

// 看似安全的清理工具类
package com.bank.portal.util;

public class SanitizationUtil {
    public static String cleanFileName(String filename) {
        if (filename == null) return "unknown";
        
        // 误导性安全措施：仅替换部分特殊字符
        filename = filename.replace("../", "");
        filename = filename.replace("*", "");
        
        // 漏洞根源：未处理HTML特殊字符
        return filename;
    }
}