package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceLoader;
import org.springframework.core.io.support.YamlPropertySourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileMergeController {
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/merge")
    public String mergeFileBlocks(@RequestParam String fileName) {
        try {
            return fileMergeService.processFile(fileName);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

@Service
class FileMergeService {
    private final ResourceLoader resourceLoader;
    private final PropertySourceLoader yamlLoader = new YamlPropertySourceLoader();

    public FileMergeService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public String processFile(String fileName) throws IOException {
        // 模拟元编程动态调用
        try {
            Class<?> clazz = Class.forName("com.example.vulnerableapp.FileProcessor");
            Method method = clazz.getMethod("loadResource", String.class);
            Resource resource = (Resource) method.invoke(clazz.newInstance(), fileName);
            
            PropertySource<?> propertySource = yamlLoader.load("custom", resource);
            return "File processed successfully: " + propertySource.toString();
            
        } catch (Exception e) {
            throw new IOException("Invalid file path: " + e.getMessage());
        }
    }
}

class FileProcessor {
    public static Resource loadResource(String fileName) {
        // 路径遍历漏洞点：用户输入直接拼接
        String basePath = "/uploads/";
        String fullPath = basePath + fileName;
        
        // 动态构造资源路径（元编程特征）
        Map<String, String> env = System.getenv();
        for (Map.Entry<String, String> entry : env.entrySet()) {
            if (fullPath.contains("$" + entry.getKey())) {
                fullPath = fullPath.replace("$" + entry.getKey(), entry.getValue());
            }
        }
        
        return new org.springframework.core.io.FileSystemResource(fullPath);
    }
}