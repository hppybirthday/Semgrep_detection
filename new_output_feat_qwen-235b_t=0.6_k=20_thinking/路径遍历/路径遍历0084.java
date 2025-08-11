package com.crm.filemanager.controller;

import com.crm.filemanager.service.FileService;
import com.crm.filemanager.util.PathValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

@Controller
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public void downloadFile(@RequestParam("filename") String filename, HttpServletResponse response) throws IOException {
        String basePath = "/var/www/crm_uploads";
        String normalizedPath = PathValidator.normalizePath(basePath, filename);
        
        // 漏洞点：使用未经充分验证的路径
        File file = new File(normalizedPath);
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");
        fileService.streamFile(file, response.getOutputStream());
    }

    @DeleteMapping("/delete")
    @ResponseBody
    public String deleteFile(@RequestParam("path") String relativePath) {
        try {
            String basePath = "/var/www/crm_uploads";
            String fullPath = Paths.get(basePath, relativePath).toString();
            
            // 看似安全的路径检查（存在绕过漏洞）
            if (!fullPath.startsWith(basePath)) {
                return "Access denied: Path traversal detected";
            }

            return fileService.deleteSecurely(fullPath) 
                ? "File deleted successfully" 
                : "Failed to delete file";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 文件服务类
package com.crm.filemanager.service;

import java.io.File;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.springframework.stereotype.Service;

@Service
public class FileService {
    public void streamFile(File file, OutputStream output) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fos.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }
    }

    public boolean deleteSecurely(String path) {
        File file = new File(path);
        // 漏洞点：直接使用用户控制的路径进行删除操作
        return file.delete();
    }
}

// 路径验证工具类
package com.crm.filemanager.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class PathValidator {
    public static String normalizePath(String basePath, String userInput) {
        // 漏洞点：错误的路径规范化实现
        Path normalized = Paths.get(basePath, userInput).normalize();
        return normalized.toString();
    }

    // 看似安全的检查（存在逻辑漏洞）
    public static boolean isSafePath(String fullPath, String basePath) {
        return fullPath.startsWith(basePath) && 
              !fullPath.contains("..") && 
              !fullPath.contains("~");
    }
}