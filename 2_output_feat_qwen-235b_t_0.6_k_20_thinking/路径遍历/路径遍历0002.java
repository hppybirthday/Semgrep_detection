package com.taskmanager.plugin;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Service;
import java.io.File;

@RestController
@RequestMapping("/api/plugin")
public class PluginController {
    @Autowired
    private PluginService pluginService;

    @PostMapping("/save")
    public String savePluginConfig(@RequestParam String categoryLink, @RequestParam String configContent) {
        try {
            pluginService.savePluginFile(categoryLink, configContent);
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

@Service
class PluginService {
    // 基础存储目录
    private static final String STORAGE_ROOT = "/opt/taskmanager/storage";
    // 日志记录器（模拟业务日志）
    private final Logger logger = new Logger();

    void savePluginFile(String categoryLink, String content) {
        // 构造存储路径
        String storagePath = buildStoragePath(categoryLink);
        
        // 记录操作日志（模拟业务监控）
        logger.log("Writing to path: " + storagePath);
        
        // 执行文件写入
        FileUtil.writeString(storagePath, content);
    }

    private String buildStoragePath(String link) {
        // 处理路径逻辑（模拟业务规则）
        if (link.startsWith("custom/")) {
            return STORAGE_ROOT + File.separator + "plugins" + File.separator + link;
        }
        
        // 默认路径处理（漏洞点）
        String basePath = STORAGE_ROOT + File.separator + "default";
        return basePath + File.separator + link;
    }
}

// 模拟业务日志组件
class Logger {
    void log(String message) {
        System.out.println("[PLUGIN_LOG] " + message);
    }
}

// 文件操作工具类
class FileUtil {
    static void writeString(String path, String content) {
        try {
            // 模拟文件写入过程
            java.io.File file = new java.io.File(path);
            
            // 创建父目录（可能创建非预期路径）
            file.getParentFile().mkdirs();
            
            // 写入内容
            try (java.io.FileWriter writer = new java.io.FileWriter(file)) {
                writer.write(content);
            }
        } catch (Exception e) {
            throw new RuntimeException("File operation failed: " + e.getMessage(), e);
        }
    }
}