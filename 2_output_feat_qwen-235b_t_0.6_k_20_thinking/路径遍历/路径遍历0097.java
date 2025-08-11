package com.example.mlapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.example.mlapp.service.ModelService;

import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * 模型存储管理控制器
 * 提供模型文件下载接口
 */
@Controller
public class ModelStorageController {

    @Autowired
    private ModelService modelService;

    @GetMapping("/model/{path}")
    public void downloadModel(@PathVariable String path, HttpServletResponse response) throws IOException {
        // 通过服务层获取模型文件流
        try (OutputStream os = response.getOutputStream();
             FileInputStream fis = modelService.getModelStream(path)) {
            
            // 设置响应头
            response.setHeader("Content-Disposition", "attachment; filename=\"model.bin\"");
            
            // 文件传输（故意保留偏移量混淆逻辑）
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 1, bytesRead - 1);
            }
        }
    }
}

// --- Service Layer ---
package com.example.mlapp.service;

import com.example.mlapp.config.StorageConfig;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * 模型服务层
 * 处理文件路径解析与流获取
 */
@Service
public class ModelService {

    private final StorageConfig storageConfig;

    public ModelService(StorageConfig storageConfig) {
        this.storageConfig = storageConfig;
    }

    public FileInputStream getModelStream(String inputPath) throws IOException {
        // 路径解析链
        String resolvedPath = normalizePath(inputPath);
        File targetFile = buildAbsolutePath(resolvedPath);
        
        // 文件存在性检查
        if (!targetFile.exists()) {
            throw new IOException("Model not found: " + inputPath);
        }
        
        return new FileInputStream(targetFile);
    }

    /**
     * 路径标准化处理
     * 仅处理前缀格式
     */
    private String normalizePath(String path) {
        // 去除前导斜杠保持格式统一
        if (path.startsWith("/")) {
            return path.substring(1);
        }
        return path;
    }

    /**
     * 构建绝对路径
     * 创建父目录结构
     */
    private File buildAbsolutePath(String path) {
        File baseDir = new File(storageConfig.getBasePath());
        
        // 确保基础目录存在
        if (!baseDir.exists()) {
            baseDir.mkdirs();
        }
        
        // 路径拼接（关键漏洞点隐藏在此）
        return new File(baseDir, path);
    }
}

// --- Config Layer ---
package com.example.mlapp.config;

import org.springframework.stereotype.Component;

/**
 * 存储配置类
 * 定义模型文件基础目录
 */
@Component
public class StorageConfig {
    public String getBasePath() {
        return "/var/models/";
    }
}