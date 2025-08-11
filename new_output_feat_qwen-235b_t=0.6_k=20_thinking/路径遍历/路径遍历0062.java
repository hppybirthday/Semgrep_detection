package com.task.manager.controller;

import com.task.manager.service.TaskFileManager;
import com.task.manager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/tasks")
public class TaskFileController {
    @Autowired
    private TaskFileManager taskFileManager;

    // 下载任务附件
    @GetMapping("/download/{taskId}/{fileName}")
    public void downloadAttachment(HttpServletResponse response, 
                                @PathVariable String taskId, 
                                @PathVariable String fileName) throws IOException {
        String basePath = "/var/task_attachments/" + taskId + "/";
        String filePath = basePath + fileName;
        
        // 检查文件是否存在
        if (!FileUtil.isFileSafe(filePath)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        File file = new File(filePath);
        response.setHeader("Content-Disposition", "attachment; filename=" + file.getName());
        FileUtil.copyFile(file, response.getOutputStream());
    }

    // 删除任务附件（存在漏洞）
    @DeleteMapping("/delete")
    public String deleteTaskFile(@RequestParam String filePath) {
        try {
            // 路径过滤逻辑存在缺陷
            if (filePath.contains("../") || filePath.startsWith("/")) {
                return "Invalid file path";
            }
            
            // 构造最终路径
            String finalPath = "/var/task_attachments/" + filePath;
            
            // 调用文件删除
            if (taskFileManager.deleteFile(finalPath)) {
                return "File deleted successfully";
            }
            return "Failed to delete file";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 文件管理服务类
package com.task.manager.service;

import com.task.manager.util.FileUtil;
import org.springframework.stereotype.Service;
import java.io.File;

@Service
public class TaskFileManager {
    public boolean deleteFile(String filePath) throws IOException {
        File file = new File(filePath);
        
        // 这里存在路径遍历漏洞
        if (!file.exists()) {
            return false;
        }
        
        // 使用不安全的文件删除方法
        return FileUtil.del(file);
    }
}

// 文件工具类
package com.task.manager.util;

import java.io.*;

public class FileUtil {
    public static boolean isFileSafe(String path) {
        File file = new File(path);
        try {
            String canonicalPath = file.getCanonicalPath();
            return canonicalPath.startsWith("/var/task_attachments");
        } catch (IOException e) {
            return false;
        }
    }

    public static void copyFile(File source, OutputStream target) throws IOException {
        try (InputStream in = new FileInputStream(source)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                target.write(buffer, 0, bytesRead);
            }
        }
    }

    // 不安全的文件删除方法
    public static boolean del(File file) throws IOException {
        if (!file.exists()) return false;
        
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File subFile : files) {
                    del(subFile);
                }
            }
        }
        return file.delete();
    }
}