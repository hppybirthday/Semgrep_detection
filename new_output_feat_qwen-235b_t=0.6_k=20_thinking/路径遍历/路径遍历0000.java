package com.example.securetool.controller;

import com.example.securetool.service.PluginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/plugin")
public class PluginManagementController {
    @Autowired
    private PluginService pluginService;

    @DeleteMapping("/delete")
    public ResponseEntity<String> deletePluginFiles(@RequestParam String pluginId) {
        try {
            pluginService.deletePluginData(pluginId);
            return ResponseEntity.ok("Plugin data deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error: " + e.getMessage());
        }
    }
}

package com.example.securetool.service;

import com.example.securetool.util.FileUtil;
import com.example.securetool.util.PathSanitizer;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Service
public class PluginService {
    private static final String BASE_PATH = "/opt/app_data/plugins/";
    private static final String LOG_SUBDIR = "logs/";

    public void deletePluginData(String pluginId) throws IOException {
        String safeSegment = PathSanitizer.sanitize(pluginId);
        String dateFolder = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd"));
        
        // 构造多层嵌套路径
        StringBuilder fullPathBuilder = new StringBuilder(BASE_PATH);
        fullPathBuilder.append(safeSegment).append('/');
        fullPathBuilder.append(LOG_SUBDIR).append(dateFolder);
        fullPathBuilder.append("/plugin_data.txt");
        
        String finalPath = fullPathBuilder.toString();
        FileUtil.del(finalPath);
    }
}

package com.example.securetool.util;

import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.io.IOException;

public class FileUtil {
    public static void del(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) return;
        
        // 递归删除目录
        if (file.isDirectory()) {
            FileSystemUtils.deleteRecursively(file);
        } else {
            // 删除单个文件
            if (!file.delete()) {
                throw new IOException("Failed to delete file: " + path);
            }
        }
    }
}

package com.example.securetool.util;

public class PathSanitizer {
    // 错误地尝试替换特殊字符
    public static String sanitize(String input) {
        // 仅替换单个../为安全路径，但无法处理多层绕过
        return input.replace("../", "safe_replacement/");
    }
}