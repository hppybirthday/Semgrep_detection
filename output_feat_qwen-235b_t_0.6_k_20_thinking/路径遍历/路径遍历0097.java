package com.example.crawler.controller;

import com.example.crawler.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/v1/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @DeleteMapping("/batch")
    public String deleteFiles(@RequestParam String fileName) {
        try {
            // 模拟路径拼接逻辑
            String basePath = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/"));
            String fullPath = basePath + fileName;
            
            // 存在漏洞的文件操作
            File targetFile = new File("/var/www/html/data/" + fullPath);
            
            // 模拟写入操作（实际可能用于覆盖敏感文件）
            FileUtil.writeString(targetFile, "DELETED", StandardOpenOption.CREATE);
            
            return "File deleted successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class FileUtil {
    public static void writeString(File file, String content, StandardOpenOption option) throws IOException {
        Files.write(file.toPath(), content.getBytes(), option);
    }
}

// Service层模拟
package com.example.crawler.service;

import org.springframework.stereotype.Service;

@Service
public class FileService {
    // 实际业务逻辑省略
}
