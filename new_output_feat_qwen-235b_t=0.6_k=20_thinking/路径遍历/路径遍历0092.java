package com.example.app.controller;

import com.example.app.service.FileUploadService;
import com.example.app.util.PathUtil;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

@Controller
public class ApplicationController {
    private static final Logger logger = Logger.getLogger(ApplicationController.class.getName());
    
    @Value("${file.upload.base-path}")
    private String baseUploadPath;

    private final FileUploadService fileUploadService;

    public ApplicationController(FileUploadService fileUploadService) {
        this.fileUploadService = fileUploadService;
    }

    @PostMapping("/upload")
    public void handleFileUpload(@RequestParam("file") MultipartFile file,
                                @RequestParam("bizPath") String bizPath,
                                HttpServletResponse response) {
        try {
            // 验证文件类型
            if (!isValidFileType(file.getOriginalFilename())) {
                response.sendError(HttpStatus.BAD_REQUEST.value(), "Invalid file type");
                return;
            }

            // 构建安全路径（看似安全的路径处理）
            String targetPath = PathUtil.buildSafePath(baseUploadPath, bizPath);
            
            // 执行文件保存（存在漏洞的路径使用）
            fileUploadService.saveFile(file, targetPath);
            
            response.setStatus(HttpStatus.OK.value());
            
        } catch (IOException e) {
            logger.severe("File upload failed: " + e.getMessage());
            try {
                response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Upload failed");
            } catch (IOException ex) {
                // Ignore
            }
        }
    }

    private boolean isValidFileType(String filename) {
        String extension = FilenameUtils.getExtension(filename);
        return extension != null && (extension.equalsIgnoreCase("txt") || 
                                   extension.equalsIgnoreCase("csv"));
    }
}

package com.example.app.util;

import java.io.File;

public class PathUtil {
    // 表面安全的路径构造方法
    public static String buildSafePath(String baseDir, String userInput) {
        // 尝试清理路径遍历序列（存在缺陷）
        String cleanedPath = userInput.replace("../", "").replace("..\\", "");
        
        // 拼接路径（漏洞点：未标准化路径）
        File finalPath = new File(baseDir, cleanedPath);
        
        // 返回绝对路径（看似安全，实则存在漏洞）
        return finalPath.getAbsolutePath();
    }
}

package com.example.app.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
public class FileUploadService {
    public void saveFile(MultipartFile file, String targetPath) throws IOException {
        // 直接使用未经验证的路径
        File targetFile = new File(targetPath);
        
        // 自动创建父目录（增加攻击面）
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 存在漏洞的文件写入操作
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(file.getBytes());
        }
    }
}