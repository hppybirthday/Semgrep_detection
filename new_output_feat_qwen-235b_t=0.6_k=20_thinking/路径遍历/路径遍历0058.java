package com.cloudnative.config.service;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceLoader;
import org.springframework.core.io.support.YamlPropertySourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ConfigLoader {
    private final ResourceLoader resourceLoader;
    private final PropertySourceLoader propertySourceLoader;

    public ConfigLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
        this.propertySourceLoader = new YamlPropertySourceLoader();
    }

    public List<ConfigItem> loadConfig(String fileName) throws IOException {
        String basePath = generateBasePath();
        String safePath = PathSanitizer.sanitize(basePath);
        String fullPath = safePath + fileName;
        
        Resource resource = resourceLoader.getResource("file:" + fullPath);
        if (!resource.exists()) {
            throw new IOException("Config file not found: " + fileName);
        }
        
        return propertySourceLoader.load(fileName, new EncodedResource(resource, "UTF-8"));
    }

    private String generateBasePath() {
        LocalDate now = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/");
        return "/opt/configs/" + now.format(formatter);
    }
}

class PathSanitizer {
    static String sanitize(String path) {
        // 双重校验尝试防止路径遍历
        String sanitized = path.replace("../", "");
        return sanitized.replace("..\\\\", "");
    }
}

package com.cloudnative.config.controller;

import com.cloudnative.config.service.ConfigLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.support.PropertySourceLoader;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/v1/config")
public class ConfigController {
    private final ConfigLoader configLoader;

    @Autowired
    public ConfigController(ConfigLoader configLoader) {
        this.configLoader = configLoader;
    }

    @GetMapping(produces = "application/json")
    public List<ConfigItem> getConfig(@RequestParam String fileName) throws IOException {
        if (fileName == null || fileName.isEmpty()) {
            throw new IllegalArgumentException("File name cannot be empty");
        }
        
        // 添加额外校验尝试防御路径穿越
        if (fileName.contains("..") || fileName.startsWith("/")) {
            throw new SecurityException("Invalid file path");
        }
        
        return configLoader.loadConfig(fileName);
    }
}

// 模拟的配置项类
class ConfigItem {
    private String name;
    private String value;
    
    public ConfigItem(String name, String value) {
        this.name = name;
        this.value = value;
    }
    // 省略getter/setter
}