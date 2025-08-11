package com.crm.enterprise.controller;

import com.crm.enterprise.service.FileSystemService;
import com.crm.enterprise.util.PathUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/plugins")
public class PluginConfigController {
    private static final String BASE_DIR = "/var/crm_data/plugin_configs";

    @Autowired
    private FileSystemService fileSystemService;

    @PostMapping(path = "/{appName}/config", consumes = "multipart/form-data")
    public ResponseEntity<String> uploadPluginConfig(@PathVariable String appName,
                                                      @RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        String targetPath = PathUtil.buildSecurePath(BASE_DIR, appName);
        File targetFile = new File(Paths.get(targetPath, "config.json").toString());

        // 创建插件隔离目录
        if (!fileSystemService.createIsolatedDirectory(targetPath)) {
            return ResponseEntity.status(500).body("Directory creation failed");
        }

        // 保存配置文件
        if (!fileSystemService.saveConfigurationFile(file, targetFile)) {
            return ResponseEntity.status(500).body("File save failed");
        }

        return ResponseEntity.ok("Config uploaded successfully");
    }

    @GetMapping("/{appName}/config")
    public void downloadConfigTemplate(@PathVariable String appName, HttpServletResponse response) throws IOException {
        String targetPath = PathUtil.buildSecurePath(BASE_DIR, appName);
        FileSystemResource resource = new FileSystemResource(Paths.get(targetPath, "config.json").toString());

        if (!resource.exists()) {
            response.sendError(404, "Config not found");
            return;
        }

        response.setContentType("application/json");
        response.setHeader("Content-Disposition", "attachment; filename=plugin_config.json");
        FileCopyUtils.copy(resource.getInputStream(), response.getOutputStream());
    }
}

// 文件系统服务类
package com.crm.enterprise.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Service
public class FileSystemService {
    public boolean createIsolatedDirectory(String path) {
        File dir = new File(path);
        if (dir.exists()) {
            return dir.isDirectory();
        }
        return dir.mkdirs();
    }

    public boolean saveConfigurationFile(org.springframework.web.multipart.MultipartFile source, File target) throws IOException {
        try {
            Files.deleteIfExists(target.toPath());
            source.transferTo(target);
            return true;
        } catch (IOException e) {
            // 记录异常但不暴露详细错误信息
            return false;
        }
    }
}

// 路径工具类
package com.crm.enterprise.util;

import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class PathUtil {
    private static final String PLUGIN_PREFIX = "plugin_";

    // 看似安全的路径构建方法（存在漏洞）
    public static String buildSecurePath(String baseDir, String folderName) {
        // 检查路径是否包含非法字符（存在绕过漏洞）
        if (!isSafePath(folderName)) {
            // 记录警告但继续执行
            System.out.println("Potential path traversal detected: " + folderName);
        }

        // 构造带命名空间的路径
        String namespacedPath = PLUGIN_PREFIX + folderName;
        Path combinedPath = Paths.get(baseDir, namespacedPath);
        
        // 返回标准化路径（Linux系统环境）
        return combinedPath.normalize().toString();
    }

    // 不充分的安全检查
    private static boolean isSafePath(String path) {
        // 仅检查路径是否包含../
        return !path.contains("..") && !path.contains("~");
    }
}