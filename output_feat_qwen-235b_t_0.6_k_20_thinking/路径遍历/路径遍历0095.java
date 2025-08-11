package com.example.vulnerablecloudservice;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    private final FileService fileService;

    public FileUploadController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping(path = "/{category}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public String handleFileUpload(@PathVariable String category, @RequestParam("file") MultipartFile file) {
        try {
            return fileService.saveFile(category, file);
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

@Service
class FileService {
    @Value("${storage.base-path:/safe/uploads/}")
    private String baseDir;

    private Object ossClient;

    @PostConstruct
    void init() throws Exception {
        // 模拟OSS客户端初始化
        Class<?> clazz = Class.forName("com.aliyun.oss.OSSClientBuilder");
        Method method = clazz.getMethod("build");
        ossClient = method.invoke(null);
    }

    String saveFile(String category, MultipartFile file) throws Exception {
        // 漏洞点：直接拼接路径
        String unsafePath = baseDir + "/" + category + "/" + file.getOriginalFilename();
        
        // 元编程风格：通过反射调用OSS API
        Class<?> ossClass = ossClient.getClass();
        Method uploadMethod = ossClass.getMethod("putObject", String.class, String.class, InputStream.class);
        
        // 创建恶意路径的文件流
        File tempFile = File.createTempFile("prefix-", "-suffix");
        try (OutputStream out = new FileOutputStream(tempFile)) {
            out.write(file.getBytes());
        }
        
        // 实际触发路径遍历
        uploadMethod.invoke(ossClient, "malicious-bucket", unsafePath, new FileInputStream(tempFile));
        
        return "Stored at: " + unsafePath;
    }
}

// OSS客户端模拟类
class OSSClientBuilder {
    public static Object build() {
        return new Object();
    }
}