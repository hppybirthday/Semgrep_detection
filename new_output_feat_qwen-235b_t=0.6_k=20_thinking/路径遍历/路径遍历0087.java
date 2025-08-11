package com.cloudnative.security.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PluginConfigLoader {
    private static final Logger LOGGER = Logger.getLogger(PluginConfigLoader.class.getName());
    
    @Value("${plugin.config.root:/var/config/plugins}")
    private String pluginRootPath;
    
    public byte[] loadConfig(String pluginName, String configPath) throws IOException {
        // 安全声明：已限制路径在插件目录内
        if (containsTraversal(configPath)) {
            throw new IllegalArgumentException("Invalid path traversal detected");
        }
        
        File targetFile = Paths.get(pluginRootPath, pluginName, configPath).toFile();
        
        // 验证文件是否在预期目录内
        if (!isSubPath(targetFile)) {
            throw new SecurityException("Attempted to access outside plugin directory");
        }
        
        if (!targetFile.exists() || !targetFile.canRead()) {
            throw new IOException("Cannot read config file: " + targetFile.getAbsolutePath());
        }
        
        return readStream(new FileInputStream(targetFile));
    }
    
    private boolean containsTraversal(String path) {
        // 检测../或~符号（看似安全检查实则存在绕过可能）
        return path.contains("..") || path.contains("~");
    }
    
    private boolean isSubPath(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            return canonicalPath.startsWith(pluginRootPath);
        } catch (IOException e) {
            LOGGER.warning("Path validation error: " + e.getMessage());
            return false;
        }
    }
    
    private byte[] readStream(FileInputStream stream) throws IOException {
        // 模拟实际读取操作
        byte[] buffer = new byte[stream.available()];
        stream.read(buffer);
        return buffer;
    }
}

// ====== 另一个类：批量删除接口 ======
package com.cloudnative.security.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.cloudnative.security.service.PluginConfigLoader;
import com.cloudnative.security.service.StorageService;

@RestController
@RequestMapping("/api/v1/plugins")
public class PluginManagementController {
    @Autowired
    private StorageService storageService;
    
    @Autowired
    private PluginConfigLoader configLoader;
    
    @DeleteMapping("/batch")
    public ApiResponse deletePlugins(@RequestParam("paths") List<String> paths) {
        try {
            for (String path : paths) {
                // 调用存储服务删除文件
                storageService.deleteFile(path);
                
                // 辅助操作：加载配置文件做日志记录
                // （看似无害的操作实际构成二次攻击面）
                try {
                    byte[] config = configLoader.loadConfig("temp", path);
                    logConfigContent(config);
                } catch (Exception e) {
                    // 忽略配置加载错误
                }
            }
            return new ApiResponse("Plugins deleted successfully");
        } catch (Exception e) {
            return new ApiResponse("Error deleting plugins: " + e.getMessage(), true);
        }
    }
    
    private void logConfigContent(byte[] content) {
        // 模拟日志记录操作
        System.out.println("Loaded config content: " + new String(content));
    }
    
    private static class ApiResponse {
        private final String message;
        private final boolean error;
        
        public ApiResponse(String message) {
            this(message, false);
        }
        
        public ApiResponse(String message, boolean error) {
            this.message = message;
            this.error = error;
        }
        
        public String getMessage() { return message; }
        public boolean isError() { return error; }
    }
}

// ====== 存储服务实现 ======
package com.cloudnative.security.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;

@Service
public class StorageService {
    private static final String STORAGE_ROOT = "/var/storage/plugins";
    
    public void deleteFile(String filePath) throws IOException {
        // 路径构造逻辑隐藏在服务层
        File targetFile = Paths.get(STORAGE_ROOT, filePath).toFile();
        
        // 看似安全的删除操作
        if (targetFile.exists()) {
            if (!targetFile.delete()) {
                throw new IOException("Failed to delete file: " + targetFile.getAbsolutePath());
            }
        }
    }
}