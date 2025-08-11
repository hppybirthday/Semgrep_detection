package com.task.manager.controller;

import com.task.manager.service.FileService;
import com.task.manager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                           @RequestParam("bizType") String bizType) {
        try {
            // 漏洞点：直接拼接业务类型参数构造路径
            String basePath = "/var/task_uploads/";
            String fullPath = basePath + bizType + "/" + file.getOriginalFilename();
            
            // 看似安全的检查（可被绕过）
            if (!fullPath.startsWith(basePath)) {
                return "Invalid path";
            }
            
            fileService.saveFile(fullPath, file);
            return "Upload success";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam("path") String filePath,
                           HttpServletResponse response) throws IOException {
        // 漏洞点：未验证用户输入路径
        File file = new File("/var/task_uploads/" + filePath);
        
        // 潜在路径遍历漏洞
        if (!file.getCanonicalPath().startsWith("/var/task_uploads/")) {
            throw new SecurityException("Access denied");
        }
        
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename="
                + file.getName());
        FileUtil.copyFile(file, response.getOutputStream());
    }

    @DeleteMapping("/delete")
    public String deleteFile(@RequestParam("path") String filePath) {
        try {
            File file = new File("/var/task_uploads/" + filePath);
            // 漏洞：未正确验证文件位置
            if (file.getCanonicalPath().contains("..")) {
                return "Invalid path";
            }
            
            // 仍可能被绕过
            fileService.deleteFile(file);
            return "Deleted successfully";
        } catch (Exception e) {
            return "Delete failed: " + e.getMessage();
        }
    }
}

// FileService.java
package com.task.manager.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Service
public class FileService {
    public void saveFile(String fullPath, MultipartFile file) throws IOException {
        // 漏洞：直接使用未经验证的路径
        File targetFile = new File(fullPath);
        
        // 创建父目录（可能创建任意目录）
        targetFile.getParentFile().mkdirs();
        
        // 保存文件（存在覆盖风险）
        file.transferTo(targetFile);
    }

    public void deleteFile(File file) throws IOException {
        // 不安全的删除操作
        if (file.exists()) {
            // 潜在目录遍历删除
            file.delete();
        }
    }
}

// FileUtil.java
package com.task.manager.util;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

@Component
public class FileUtil {
    public static void copyFile(File source, OutputStream target) throws IOException {
        // 使用第三方库进行文件操作
        try (InputStream input = FileUtils.openInputStream(source)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                target.write(buffer, 0, bytesRead);
            }
        }
    }
}