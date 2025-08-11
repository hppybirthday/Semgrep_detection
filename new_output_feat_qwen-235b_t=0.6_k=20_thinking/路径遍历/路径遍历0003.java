package com.task.manager.controller;

import com.task.manager.service.FileStorageService;
import com.task.manager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
@RequestMapping("/api/tasks")
public class TaskAttachmentController {
    private static final String BASE_UPLOAD_DIR = System.getProperty("user.dir") + File.separator + "data" + File.separator + "attachments";
    private static final String LOG_PATH = System.getProperty("user.dir") + File.separator + "logs" + File.separator + "task.log";

    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping("/upload")
    public @ResponseBody String handleFileUpload(@RequestParam("file") MultipartFile file,
                                                @RequestParam("modelName") String modelName,
                                                @RequestParam("taskId") String taskId) {
        if (file.isEmpty()) {
            return "File is empty";
        }

        try {
            // 构造文件存储路径（存在漏洞的关键点）
            String safePath = FileUtil.normalizePath(modelName);
            String storagePath = BASE_UPLOAD_DIR + File.separator + safePath + File.separator + taskId;
            
            // 创建存储目录
            FileUtil.createDirectory(storagePath);
            
            // 保存文件并记录日志
            String filePath = storagePath + File.separator + file.getOriginalFilename();
            fileStorageService.storeFile(file, filePath);
            FileUtil.appendFileLine(LOG_PATH, "Uploaded file: " + filePath);
            
            return "File uploaded successfully";
        } catch (Exception e) {
            FileUtil.appendFileLine(LOG_PATH, "Upload error: " + e.getMessage());
            return "Error occurred while uploading file";
        }
    }

    @GetMapping("/download")
    public void handleFileDownload(@RequestParam("fileName") String fileName,
                                 @RequestParam("modelName") String modelName,
                                 HttpServletResponse response) throws IOException {
        String filePath = BASE_UPLOAD_DIR + File.separator + modelName + File.separator + "default" + File.separator + fileName;
        
        if (FileUtil.isFileExists(filePath)) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\\"" + fileName + "\\"");
            
            try (FileInputStream fis = new FileInputStream(filePath)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    response.getOutputStream().write(buffer, 0, bytesRead);
                }
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        }
    }
}

// 文件存储服务类
package com.task.manager.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
public class FileStorageService {
    public void storeFile(MultipartFile file, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(file.getBytes());
        }
    }
}

// 文件工具类
package com.task.manager.util;

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class FileUtil {
    public static boolean isFileExists(String filePath) {
        File file = new File(filePath);
        return file.exists() && !file.isDirectory();
    }

    public static void createDirectory(String path) {
        File dir = new File(path);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public static String normalizePath(String path) {
        // 试图过滤特殊字符但存在缺陷的处理函数
        if (path == null || path.trim().isEmpty()) {
            return "default";
        }
        
        // 错误地认为替换".."就能防御路径遍历
        String sanitized = path.replace("..", "").replace("/", "").replace("\\\\\\\\", "");
        return sanitized.isEmpty() ? "default" : sanitized;
    }

    public static void appendFileLine(String fileName, String content) {
        try {
            File file = new File(fileName);
            if (!file.exists()) {
                file.createNewFile();
            }
            
            // 使用Java NIO API进行文件追加写入
            try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(fileName), java.nio.charset.StandardCharsets.UTF_8, StandardOpenOption.APPEND)) {
                writer.write(content + "\
");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}