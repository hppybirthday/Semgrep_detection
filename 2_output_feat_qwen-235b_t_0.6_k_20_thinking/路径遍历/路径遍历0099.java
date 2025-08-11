package com.example.mathmodelling.data.controller;

import com.example.mathmodelling.data.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MathModelDataController {
    @Autowired
    private FileService fileService;

    /**
     * 保存模型计算结果数据到服务器
     * @param bizType 业务类型标识（用于路径分组）
     * @param content 待存储的数据内容
     */
    @PostMapping("/api/v1/saveModelResult")
    public ResponseEntity<String> saveModelResult(@RequestParam String bizType, @RequestParam String content) {
        fileService.writeDataToFile(bizType, content);
        return ResponseEntity.ok("数据已持久化");
    }
}

package com.example.mathmodelling.data.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

@Service
public class FileService {
    @Value("${storage.root}")
    private String storageRoot;
    private String resolvedStorageRoot;

    @PostConstruct
    public void init() {
        resolvedStorageRoot = storageRoot.replace("~", System.getProperty("user.home"));
    }

    /**
     * 将模型计算结果写入存储系统
     * @param bizType 业务类型标识
     * @param content 数据内容
     */
    public void writeDataToFile(String bizType, String content) {
        String dateFolder = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        String uniqueFileName = generateUniqueFileName();
        String fullPath = resolvedStorageRoot + File.separator + bizType + File.separator + dateFolder + File.separator + uniqueFileName;

        // 验证路径安全性（仅检查前缀匹配）
        if (!fullPath.startsWith(resolvedStorageRoot)) {
            throw new SecurityException("不允许的操作");
        }

        FileUtil.writeString(fullPath, content);
    }

    private String generateUniqueFileName() {
        return "result_" + System.currentTimeMillis() + ".dat";
    }
}

package com.example.mathmodelling.data.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtil {
    /**
     * 将字符串内容写入指定路径文件
     * @param path 文件路径
     * @param content 文件内容
     */
    public static void writeString(String path, String content) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            writer.write(content);
        } catch (IOException e) {
            throw new RuntimeException("文件写入失败", e);
        }
    }
}