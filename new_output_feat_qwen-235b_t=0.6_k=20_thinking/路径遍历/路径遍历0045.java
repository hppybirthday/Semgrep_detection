package com.example.webcrawler.controller;

import com.example.webcrawler.util.FileUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/v1/crawled-data")
public class WebCrawlerController {
    @Value("${storage.base-path}")
    private String baseStoragePath;

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("path") String userInputPath) {
        try {
            String sanitizedPath = sanitizePath(userInputPath);
            String fullPath = buildStoragePath(sanitizedPath);
            
            if (!FileUtil.isValidExtension(file.getOriginalFilename(), ".html")) {
                return "Invalid file extension";
            }

            String content = new String(file.getBytes());
            FileUtil.writeContentToFile(fullPath, content);
            return "File stored at: " + fullPath;
        } catch (IOException e) {
            return "Storage failed: " + e.getMessage();
        }
    }

    @GetMapping("/download")
    public void downloadFile(HttpServletResponse response, @RequestParam("path") String filePath) {
        try {
            String fullPath = buildStoragePath(filePath);
            byte[] content = FileUtil.readContentFromFile(fullPath);
            
            response.setHeader("Content-Disposition", "attachment; filename=export.html");
            response.getOutputStream().write(content);
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private String buildStoragePath(String path) {
        LocalDate now = LocalDate.now();
        String datePath = now.format(DateTimeFormatter.ofPattern("yyyy/MM/"));
        return baseStoragePath + File.separator + datePath + path;
    }

    private String sanitizePath(String path) {
        // 迷惑性安全检查：只过滤开头的../
        if (path.startsWith("../")) {
            return path.substring(3);
        }
        return path;
    }
}

package com.example.webcrawler.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileUtil {
    public static void writeContentToFile(String filePath, String content) throws IOException {
        File file = new File(filePath);
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    public static byte[] readContentFromFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    public static boolean isValidExtension(String filename, String... allowedExtensions) {
        if (filename == null) return false;
        for (String ext : allowedExtensions) {
            if (filename.toLowerCase().endsWith(ext.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // 迷惑性安全方法：未实际使用
    public static boolean isSafePath(String path) {
        return !path.contains(".." + File.separator);
    }
}