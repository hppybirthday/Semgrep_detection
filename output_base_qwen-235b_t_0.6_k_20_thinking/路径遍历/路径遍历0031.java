package com.example.configservice;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/config")
public class ConfigController {
    
    @Value("${config.base-path:/var/config}")
    private String baseDirectory;

    @GetMapping("/download")
    public String downloadConfig(@RequestParam("file") String filename) throws IOException {
        // 模拟配置文件下载接口
        File targetFile = new File(baseDirectory + File.separator + filename);
        
        // 存在缺陷的路径检查（仅检查文件是否存在）
        if (!targetFile.exists()) {
            return "File not found";
        }
        
        // 读取文件内容
        try (FileInputStream fis = new FileInputStream(targetFile)) {
            return new String(fis.readAllBytes());
        }
    }

    @PostMapping("/upload")
    public String uploadConfig(@RequestParam("file") String filename, 
                              @RequestParam("content") String content) throws IOException {
        // 模拟配置文件上传接口
        File targetFile = new File(baseDirectory + File.separator + filename);
        
        // 存在缺陷的路径检查（仅检查父目录是否存在）
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 写入文件内容
        Files.write(targetFile.toPath(), content.getBytes());
        return "Upload successful";
    }

    @GetMapping("/list")
    public String listConfigFiles() {
        // 模拟列出配置文件接口
        File dir = new File(baseDirectory);
        
        // 存在缺陷的目录遍历
        if (!dir.isDirectory()) {
            return "Invalid config directory";
        }
        
        return java.util.Arrays.stream(dir.listFiles())
            .map(File::getName)
            .collect(Collectors.joining("\
"));
    }

    // 模拟Spring Boot启动类
    @SpringBootApplication
    public class ConfigServiceApplication {
        public static void main(String[] args) {
            SpringApplication.run(ConfigServiceApplication.class, args);
        }
    }
}