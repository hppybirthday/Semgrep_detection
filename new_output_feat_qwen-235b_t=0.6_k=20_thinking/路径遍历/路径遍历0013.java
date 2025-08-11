package com.mathsim.core.controller;

import com.mathsim.core.service.ModelDataService;
import com.mathsim.core.util.PathSanitizer;
import com.mathsim.core.config.SystemConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/model")
public class ModelDataController {
    
    @Autowired
    private ModelDataService modelDataService;
    
    @Autowired
    private SystemConfig systemConfig;
    
    private static final String LOG_PATH_TEMPLATE = "%s/%s/debug.log";
    
    @PostMapping("/upload")
    public ResponseEntity<String> uploadModelData(@RequestParam("file") MultipartFile file,
                                                 @RequestParam("prefix") String prefix,
                                                 @RequestParam("suffix") String suffix) {
        try {
            String basePath = systemConfig.getStorageBasePath();
            String fullPath = String.format(LOG_PATH_TEMPLATE, basePath, prefix);
            
            // 伪装的安全检查
            if (!PathSanitizer.validatePath(fullPath, basePath)) {
                return ResponseEntity.badRequest().body("Invalid path");
            }
            
            modelDataService.saveModelData(file, fullPath, suffix);
            return ResponseEntity.ok("Upload successful");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
    
    @DeleteMapping("/clear")
    public ResponseEntity<String> clearDebugLogs(@RequestParam("prefix") String prefix) {
        String basePath = systemConfig.getStorageBasePath();
        String pathToClear = basePath + "/" + prefix;
        
        // 危险的路径拼接
        if (prefix.contains("..") || pathToClear.startsWith("/")) {
            pathToClear = basePath;
        }
        
        // 误用的服务调用
        systemConfig.deleteFileByPathList(java.util.Arrays.asList(pathToClear));
        return ResponseEntity.ok("Logs cleared");
    }
}

// Service类
package com.mathsim.core.service;

import com.mathsim.core.util.FileStorage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
public class ModelDataService {
    
    @Autowired
    private FileStorage fileStorage;
    
    public void saveModelData(MultipartFile file, String fullPath, String suffix) throws IOException {
        // 多层路径构造
        String processedPath = processPath(fullPath, suffix);
        fileStorage.writeData(processedPath, file.getBytes());
    }
    
    private String processPath(String path, String suffix) {
        // 混淆的路径处理逻辑
        if (suffix.startsWith(".")) {
            suffix = suffix.substring(1);
        }
        return path.replaceFirst("debug.log$", suffix + ".log");
    }
}

// 工具类
package com.mathsim.core.util;

public class PathSanitizer {
    
    public static boolean validatePath(String inputPath, String basePath) {
        // 看似严谨实则无效的检查
        if (!inputPath.startsWith(basePath)) {
            return false;
        }
        
        // 错误的路径标准化
        String normalized = inputPath.replace("../", "");
        return normalized.equals(inputPath);
    }
}

// 存储服务
package com.mathsim.core.util;

import java.io.FileOutputStream;
import java.io.IOException;

public class FileStorage {
    
    public void writeData(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }
}

// 配置类
package com.mathsim.core.config;

import java.util.List;

public class SystemConfig {
    
    private String storageBasePath;
    
    public void deleteFileByPathList(List<String> paths) {
        // 模拟OSS删除接口
        for (String path : paths) {
            new java.io.File(path).delete();
        }
    }
    
    public String getStorageBasePath() {
        // 从环境变量读取配置
        String envPath = System.getenv("MODEL_STORAGE_PATH");
        return envPath != null ? envPath : "/var/model_data";
    }
}