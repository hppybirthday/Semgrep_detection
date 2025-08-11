package com.example.vulnerable.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/api/files")
public class FileDownloadController {
    private static final String BASE_PATH = "/var/files/";
    
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface FileOperation {
        String value() default "download";
    }

    @GetMapping("/download")
    public ResponseEntity<InputStreamResource> downloadFile(@RequestParam String filename) throws IOException {
        try {
            File file = new File(BASE_PATH + filename);
            
            // 元编程动态调用
            Map<String, Object> context = new HashMap<>();
            context.put("filePath", file.getAbsolutePath());
            
            Method method = FileDownloadController.class.getMethod("processFileOperation", Map.class);
            method.invoke(this, context);
            
            FileInputStream fis = new FileInputStream(file);
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + filename + "\\"")
                .body(new InputStreamResource(fis));
        } catch (Exception e) {
            throw new IOException("File access error: " + e.getMessage());
        }
    }

    @FileOperation
    public void processFileOperation(Map<String, Object> context) {
        // 模拟动态处理逻辑
        String filePath = (String) context.get("filePath");
        System.out.println("Processing file operation for: " + filePath);
        // 实际业务逻辑中可能包含更多动态处理代码
    }

    // 模拟业务扩展的额外方法
    @GetMapping("/metadata")
    @ResponseBody
    public String getFileMetadata(@RequestParam String filename) {
        File file = new File(BASE_PATH + filename);
        return "File exists: " + file.exists() + ", Size: " + file.length() + " bytes";
    }
}

// 模拟Spring Boot启动类
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}