package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;

@SpringBootApplication
public class FileUploadApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileUploadApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileController {
    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String fileName) throws IOException {
        // 使用反射动态调用服务方法
        try {
            Method method = FileService.class.getMethod("downloadFile", String.class);
            return ResponseEntity.ok((byte[]) method.invoke(fileService, fileName));
        } catch (Exception e) {
            throw new IOException("File operation failed");
        }
    }
}

class FileService {
    private static final String BASE_PATH = "/var/www/uploads";

    public byte[] downloadFile(String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入
        File file = new File(BASE_PATH + File.separator + fileName);
        
        // 模拟日志框架设置文件路径
        System.setProperty("log.file", file.getAbsolutePath());
        
        // 真实文件操作
        byte[] content = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(content);
        }
        return content;
    }
}