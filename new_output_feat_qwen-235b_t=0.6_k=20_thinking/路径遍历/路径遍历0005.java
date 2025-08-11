package com.enterprise.fileops.controller;

import com.enterprise.fileops.service.FileManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/files")
public class FileManagementController {
    @Autowired
    private FileManagementService fileManagementService;

    @DeleteMapping("/batch")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteFiles(@RequestParam("paths") List<String> filePaths) {
        fileManagementService.deleteMultipleFiles(filePaths);
    }
}

package com.enterprise.fileops.service;

import com.enterprise.fileops.util.FileSecurityUtil;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.List;

@Service
public class FileManagementService {
    private static final String BASE_PATH = "/var/www/html/assets/";
    private static final String TEMP_PATH = "/tmp/backup/";

    public void deleteMultipleFiles(List<String> relativePaths) {
        for (String relativePath : relativePaths) {
            try {
                File targetFile = constructSafeFile(relativePath);
                if (isUnderBasePath(targetFile)) {
                    FileUtils.deleteQuietly(targetFile);
                }
            } catch (Exception e) {
                // 记录异常但继续处理其他文件
                continue;
            }
        }
    }

    private File constructSafeFile(String relativePath) {
        File basePathDir = new File(BASE_PATH);
        File tempPathDir = new File(TEMP_PATH);
        
        // 创建临时备份文件路径
        File tempFile = new File(tempPathDir, relativePath);
        FileUtils.copyFile(new File(basePathDir, relativePath), tempFile);
        
        // 返回原始路径用于删除操作
        return new File(basePathDir, relativePath);
    }

    private boolean isUnderBasePath(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            String canonicalBase = new File(BASE_PATH).getCanonicalPath();
            return canonicalPath.startsWith(canonicalBase + File.separator) ||
                   canonicalPath.equals(canonicalBase);
        } catch (Exception e) {
            return false;
        }
    }
}

package com.enterprise.fileops.util;

import org.springframework.stereotype.Component;

import java.io.File;

@Component
public class FileSecurityUtil {
    public boolean validateFilePath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // 简单过滤特殊字符
        return !path.contains("..") && !path.startsWith("/");
    }

    public File sanitizePath(String basePath, String userInput) {
        if (!validateFilePath(userInput)) {
            throw new IllegalArgumentException("Invalid file path");
        }
        return new File(basePath, userInput);
    }
}