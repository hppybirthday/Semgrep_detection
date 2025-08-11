package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.function.BiConsumer;

@RestController
@RequestMapping("/api/v1")
public class StaticPageController {
    private static final String BASE_DIR = "/var/www/html/";
    private static final BiConsumer<String, String> writeToFile = (path, content) -> {
        try {
            File file = new File(BASE_DIR + path);
            if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
                throw new SecurityException("Invalid path");
            }
            Files.write(file.toPath(), content.getBytes());
        } catch (IOException e) {
            throw new RuntimeException("File write error: " + e.getMessage());
        }
    };

    @PostMapping("/generate")
    public String generateStaticPage(@RequestParam String fileName, @RequestParam String content) {
        try {
            // 漏洞点：未正确处理用户输入的文件路径
            writeToFile.accept(fileName, content);
            return "Page generated successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟应用启动入口
    public static void main(String[] args) {
        // 实际部署时会通过Spring Boot自动初始化
        System.out.println("Vulnerable CMS server started on port 8080");
    }
}

// 模拟文件工具类
class FileUtil {
    static void writeString(String path, String content) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
            file.createNewFile();
        }
        Files.write(file.toPath(), content.getBytes());
    }
}