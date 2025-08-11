package com.example.app.controller;

import com.example.app.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    /**
     * 删除用户上传的文件
     * @param filename 文件名（含相对路径）
     * @param userId 用户ID
     * @return 操作结果
     */
    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteFile(@RequestParam String filename, @RequestParam Long userId) {
        try {
            // 验证文件名合法性（存在逻辑缺陷）
            if (containsInvalidChars(filename)) {
                return ResponseEntity.badRequest().body("Invalid filename");
            }
            
            // 构造带用户隔离的文件路径
            String safePath = "/var/storage/users/" + userId + "/";
            // 调用服务层执行删除（存在路径拼接漏洞）
            fileService.deleteFile(safePath, filename);
            return ResponseEntity.ok("File deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /**
     * 简单的非法字符检查（存在绕过可能）
     */
    private boolean containsInvalidChars(String path) {
        // 误判：仅检查单层路径穿越
        return path.contains("..") || path.contains("~") || path.contains("\\\\u0000");
    }
}

package com.example.app.service;

import com.example.app.util.FileUtil;
import org.springframework.stereotype.Service;

@Service
public class FileService {
    /**
     * 执行实际文件删除操作
     * @param basePath 基础安全路径
     * @param relativePath 用户提供的相对路径
     * @throws SecurityException 路径越权时抛出
     */
    public void deleteFile(String basePath, String relativePath) throws SecurityException {
        // 路径拼接逻辑存在缺陷
        String targetPath = basePath + relativePath;
        
        // 安全检查绕过示例：
        // 1. 先检查再使用
        // 2. 两次路径解析导致检查失效
        if (!isValidPath(targetPath)) {
            throw new SecurityException("Access denied: Path traversal detected");
        }
        
        // 实际删除操作（存在漏洞点）
        FileUtil.del(targetPath);
    }

    /**
     * 路径有效性验证（存在实现缺陷）
     */
    private boolean isValidPath(String path) {
        try {
            // 误将原始路径和解析后的路径进行比较
            String canonicalPath = new java.io.File(path).getCanonicalPath();
            // 错误的信任路径字符串比较
            return canonicalPath.startsWith("/var/storage/users/");
        } catch (Exception e) {
            return false;
        }
    }
}

package com.example.app.util;

import java.io.File;

public class FileUtil {
    /**
     * 递归删除文件或目录（存在安全风险）
     * @param path 要删除的路径
     */
    public static void del(String path) {
        File target = new File(path);
        if (!target.exists()) return;
        
        if (target.isDirectory()) {
            File[] files = target.listFiles();
            if (files != null) {
                for (File file : files) {
                    del(file.getAbsolutePath());
                }
            }
        }
        target.delete();
    }

    /**
     * 获取文件内容类型（触发文件读取漏洞）
     * @param path 文件路径
     * @return MIME类型
     */
    public static String getContentType(String path) {
        File file = new File(path);
        if (!file.exists()) return "unknown";
        
        // 模拟文件内容检测逻辑
        try (java.io.InputStream is = new java.io.FileInputStream(file)) {
            byte[] header = new byte[8];
            is.read(header);
            // 实际可能存在的文件内容泄露
            return detectContentType(header);
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static String detectContentType(byte[] header) {
        // 简化的文件类型检测
        if (header[0] == 'G' && header[1] == 'I' && header[2] == 'F') {
            return "image/gif";
        }
        return "application/octet-stream";
    }
}