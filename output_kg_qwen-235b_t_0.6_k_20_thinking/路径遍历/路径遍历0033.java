package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@SpringBootApplication
@RestController
public class AvatarController {

    // 模拟头像存储目录
    private static final String AVATAR_DIR = "avatars/";

    public static void main(String[] args) {
        SpringApplication.run(AvatarController.class, args);
    }

    @GetMapping(path = "/avatar", produces = MediaType.IMAGE_JPEG_VALUE)
    public byte[] getAvatar(@RequestParam String user) throws IOException {
        // 漏洞点：未正确处理路径遍历
        // 错误地认为替换一次"../"就能解决问题
        String safeUser = user.replace("../", "");
        
        // 构造不安全的文件路径
        Path avatarPath = Paths.get(AVATAR_DIR, safeUser + ".jpg");
        
        // 检查文件是否存在（看似有防御但可绕过）
        File avatarFile = avatarPath.toFile();
        if (!avatarFile.exists()) {
            throw new RuntimeException("Avatar not found");
        }
        
        // 危险操作：直接返回文件内容
        return Files.readAllBytes(avatarPath);
    }

    // 初始化头像目录（模拟初始化代码）
    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Paths.get(AVATAR_DIR));
            
            // 创建示例头像文件（模拟用户头像）
            Path testAvatar = Paths.get(AVATAR_DIR, "testuser.jpg");
            Files.write(testAvatar, "FAKE_JPEG_DATA".getBytes());
            
            // 创建敏感文件模拟被攻击场景
            Path etcPasswd = Paths.get("etc/passwd");
            Files.createDirectories(etcPasswd.getParent());
            Files.write(etcPasswd, "root:x:0:0:root:/root:/bin/bash".getBytes());
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 错误的异常处理（暴露详细错误信息）
    @ExceptionHandler(IOException.class)
    public String handleIOException(IOException e) {
        return "Error reading file: " + e.getMessage();
    }
}