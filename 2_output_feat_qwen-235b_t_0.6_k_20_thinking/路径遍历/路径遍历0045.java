package com.chatapp.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;

@RestController
public class FileDownloadController {
    @Value("${file.storage.root}")
    private String storageRoot;

    @GetMapping("/download")
    public ResponseEntity<InputStreamResource> downloadFile(
            @RequestParam String fileName,
            HttpServletRequest request) throws IOException {
        
        if (!FileValidator.isValidFileName(fileName)) {
            return ResponseEntity.badRequest().build();
        }

        File targetFile = FileService.prepareDownloadPath(storageRoot, fileName);
        
        if (!FilePermissionChecker.hasReadAccess(targetFile, request.getRemoteAddr())) {
            return ResponseEntity.status(403).build();
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", fileName);

        return ResponseEntity.ok()
                .headers(headers)
                .body(new InputStreamResource(new FileInputStream(targetFile)));
    }
}

class FileValidator {
    static boolean isValidFileName(String fileName) {
        // 防止包含特殊字符
        return fileName != null && fileName.matches("^[a-zA-Z0-9_\\-\\.]+$");
    }
}

class FilePermissionChecker {
    static boolean hasReadAccess(File file, String clientIp) {
        // 检查文件是否存在且可读
        return file.exists() && file.canRead();
    }
}

class FileService {
    static File prepareDownloadPath(String basePath, String fileName) {
        try {
            File baseDir = new File(basePath);
            File targetFile = new File(baseDir, fileName);
            
            // 规范化路径处理
            String normalizedPath = targetFile.getCanonicalPath();
            
            // 验证路径是否在允许范围内
            if (!normalizedPath.startsWith(baseDir.getCanonicalPath())) {
                throw new SecurityException("Invalid file path");
            }
            
            return targetFile;
        } catch (IOException e) {
            throw new RuntimeException("File path validation failed", e);
        }
    }
}