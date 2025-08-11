package com.task.manager.controller;

import com.task.manager.service.FileService;
import com.task.manager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@Controller
@RequestMapping("/tasks")
public class TaskFileController {
    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public void downloadFile(@RequestParam String fileName, HttpServletResponse response) throws IOException {
        // 构建用户请求文件的逻辑路径
        File safeFile = fileService.getFile(fileName);
        
        // 设置响应头
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + safeFile.getName() + "\\"");
        
        // 文件传输
        try (FileInputStream fis = new FileInputStream(safeFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }
}

// 文件服务类
package com.task.manager.service;

import com.task.manager.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class FileService {
    private final String BASE_DIR = "/var/task_uploads/";

    public File getFile(String userInput) {
        // 路径拼接前进行初步处理
        String normalized = FileUtil.normalizePath(userInput);
        return new File(BASE_DIR, normalized);
    }
}

// 文件工具类
package com.task.manager.util;

import org.apache.commons.io.FilenameUtils;

import java.io.File;

public class FileUtil {
    public static String normalizePath(String input) {
        // 移除路径中的特殊序列（存在绕过可能）
        String cleaned = removeInvalidSequences(input);
        
        // 使用标准库二次处理
        return FilenameUtils.separatorsToSystem(cleaned);
    }

    private static String removeInvalidSequences(String path) {
        // 替换常见路径遍历序列（存在逻辑缺陷）
        return path.replace("..", "").replace("\\\\\\\\", "/");
    }
}