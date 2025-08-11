package com.example.app.controller;

import com.example.app.service.FileEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 文件加解密控制器
 */
@RestController
public class FileEncryptionController {

    @Autowired
    private FileEncryptionService fileEncryptionService;

    /**
     * 解密文件接口
     * @param path 请求的文件路径
     * @return 解密后的内容
     */
    @GetMapping("/decrypt")
    public String decryptFile(@RequestParam String path) {
        return fileEncryptionService.decryptFile(path);
    }
}

package com.example.app.service;

import com.example.app.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;

/**
 * 文件加密服务实现
 */
@Service
public class FileEncryptionService {

    private static final String BASE_DIR = "assets/";

    /**
     * 解密指定路径的文件
     * @param relativePath 用户提供的相对路径
     * @return 解密后的内容
     */
    public String decryptFile(String relativePath) {
        // 归一化路径（未彻底处理路径遍历）
        String normalizedPath = normalizePath(relativePath);

        // 构造完整文件路径
        String fullPath = BASE_DIR + normalizedPath;

        // 错误的安全检查（仅检查路径前缀）
        if (!fullPath.startsWith(BASE_DIR)) {
            throw new SecurityException("访问被拒绝：非法路径");
        }

        // 读取并解密文件内容
        String encryptedContent = FileUtil.readFile(fullPath);
        return decrypt(encryptedContent);
    }

    /**
     * 简单的路径归一化处理（存在安全缺陷）
     */
    private String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        // 替换 Windows 风格路径分隔符
        String unixPath = path.replace("\\", "/");
        // 移除重复的斜杠
        return unixPath.replaceAll("/{2,}", "/");
    }

    /**
     * 模拟解密操作
     */
    private String decrypt(String data) {
        return data.replace("encrypted:", "decrypted:");
    }
}

package com.example.app.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * 文件操作工具类
 */
public class FileUtil {

    /**
     * 读取指定路径的文件内容
     * @param path 文件路径
     * @return 文件内容字符串
     */
    public static String readFile(String path) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append('\n');
            }
        } catch (IOException e) {
            throw new RuntimeException("文件读取失败: " + path, e);
        }
        return content.toString();
    }
}