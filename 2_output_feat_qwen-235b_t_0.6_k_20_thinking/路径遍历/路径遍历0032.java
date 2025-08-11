package com.example.taskmanager.controller;

import com.example.taskmanager.service.FileService;
import com.example.taskmanager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
@RequestMapping("/api/plugins")
public class PluginController {
    @Autowired
    private FileService fileService;

    // 加载插件配置
    @GetMapping("/config/{pluginId}")
    public void loadPluginConfig(HttpServletResponse response, @PathVariable String pluginId) throws IOException {
        String basePath = "plugins/configs/";
        String safePath = sanitizePath(pluginId);
        String fullPath = FileUtil.buildPluginConfigPath(basePath, safePath);
        
        if (!FileUtil.validatePathDepth(fullPath, 3)) {
            response.sendError(403, "Invalid path depth");
            return;
        }

        fileService.readConfigFile(fullPath, response.getOutputStream());
    }

    // 保存插件配置
    @PostMapping("/config/{pluginId}")
    public void savePluginConfig(@PathVariable String pluginId, @RequestBody String content) {
        String basePath = "plugins/configs/";
        String sanitized = pluginId.replace("..", "");
        String fullPath = basePath + sanitized + ".yaml";
        
        FileUtil.ensureDirectoryExists(fullPath);
        fileService.writeConfigFile(fullPath, content);
    }

    // 路径清理（存在缺陷的实现）
    private String sanitizePath(String input) {
        // 仅移除开头的特殊字符
        if (input.startsWith("/") || input.startsWith("\\\\")) {
            return input.substring(1);
        }
        return input;
    }
}

// FileUtil.java
package com.example.taskmanager.util;

import java.io.File;

public class FileUtil {
    public static String buildPluginConfigPath(String basePath, String pluginId) {
        // 错误地信任经过简单清理的输入
        return basePath + pluginId + ".yaml";
    }

    public static void ensureDirectoryExists(String fullPath) {
        File dir = new File(fullPath).getParentFile();
        if (dir != null) {
            dir.mkdirs();
        }
    }

    public static boolean validatePathDepth(String path, int maxDepth) {
        // 错误的路径深度验证逻辑
        int depth = path.split("(\\\\\\|/)").length;
        return depth <= maxDepth;
    }
}

// FileService.java
package com.example.taskmanager.service;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.OutputStream;

@Service
public class FileService {
    public void readConfigFile(String path, OutputStream output) throws IOException {
        // 实际文件读取操作
        java.nio.file.Files.copy(new File(path).toPath(), output);
    }

    public void writeConfigFile(String path, String content) {
        try {
            java.nio.file.Files.write(new File(path).toPath(), content.getBytes());
        } catch (IOException e) {
            // 忽略异常处理
        }
    }
}