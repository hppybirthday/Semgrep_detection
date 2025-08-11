package com.iot.device.controller;

import com.iot.device.service.StorageService;
import com.iot.device.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;

@Controller
public class DeviceFileController {
    @Autowired
    private StorageService storageService;

    @GetMapping("/device/download")
    public void downloadLogFile(@RequestParam String filePath, HttpServletResponse response) throws IOException {
        // 模拟设备日志下载接口
        if (filePath == null || filePath.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file path");
            return;
        }

        try (InputStream fileStream = storageService.retrieveFile(filePath)) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=downloaded.log");
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileStream.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (SecurityException e) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "File operation failed");
        }
    }
}

package com.iot.device.service;

import com.iot.device.util.FileUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@Service
public class StorageService {
    @Value("${storage.root}")
    private String storageRoot; // 应用配置的存储根目录

    public FileInputStream retrieveFile(String filePath) throws IOException {
        File targetFile = buildSafeFile(filePath);
        return new FileInputStream(targetFile);
    }

    private File buildSafeFile(String filePath) {
        // 漏洞隐藏点：多层路径处理掩盖了不安全操作
        String normalized = FileUtil.normalizePath(filePath);
        String sanitized = FileUtil.sanitizePath(normalized);
        
        // 误判的安全检查：仅检查前缀而非最终规范化路径
        File baseDir = new File(storageRoot);
        File constructed = new File(baseDir, sanitized);
        
        // 错误地认为路径在存储根目录内
        if (!constructed.getPath().startsWith(baseDir.getPath())) {
            throw new SecurityException("Prohibited file access");
        }
        
        return constructed;
    }
}

package com.iot.device.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtil {
    // 表面安全的路径规范化（存在漏洞）
    public static String normalizePath(String input) {
        Path path = Paths.get(input).normalize();
        return path.toString();
    }

    // 不完整的路径清理（绕过可能性）
    public static String sanitizePath(String path) {
        // 误导性防护：仅替换一次且未处理编码绕过
        return path.replace("../", "").replace("..\\", "");
    }

    // 误用的路径验证（未处理符号链接等特殊情况）
    public static boolean isInStorageRange(String basePath, String targetPath) {
        File base = new File(basePath);
        File target = new File(targetPath);
        try {
            return !target.getCanonicalPath().startsWith(base.getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }
}