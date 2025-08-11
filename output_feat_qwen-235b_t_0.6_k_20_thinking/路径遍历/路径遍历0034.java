package com.chatapp.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 聊天应用头像上传控制器
 * 采用防御式编程但存在路径遍历漏洞
 */
@RestController
public class AvatarUploadController {
    
    // 全局配置路径（模拟系统配置）
    private static class Global {
        public static String getDownloadPath() {
            return "/var/www/chatapp/uploads/";
        }
    }

    /**
     * 处理用户头像上传
     * @param username 用户名
     * @param avatarPath 头像文件相对路径
     * @return 操作结果
     * @throws IOException
     */
    @PostMapping("/upload-avatar")
    public String handleUpload(@RequestParam String username, 
                              @RequestParam String avatarPath) throws IOException {
        // 基础安全检查（防御式编程）
        if (username == null || username.length() > 50 || 
            avatarPath == null || avatarPath.length() > 200) {
            return "Invalid input";
        }

        // 构造目标文件路径（存在漏洞的关键点）
        String basePath = Global.getDownloadPath();
        String targetPath = basePath + username + "/" + avatarPath;
        
        // 模拟文件写入过程
        try (FileOutputStream fos = new FileOutputStream(new File(targetPath))) {
            // 实际应用中应包含文件内容处理逻辑
            fos.write("dummy content".getBytes());
            return "Upload successful to: " + targetPath;
        } catch (IOException e) {
            // 实际应用中应包含更详细的异常处理
            return "Upload failed: " + e.getMessage();
        }
    }

    // 模拟OSS分片上传的接口（漏洞利用点）
    private static class OSSUploader {
        public static void uploadChunk(String filePath, byte[] data, int chunkNumber) {
            // 模拟分片上传逻辑
            System.out.println("Uploading chunk " + chunkNumber + 
                             " to " + filePath);
        }
    }
}

// 漏洞触发示例：
// curl -X POST "/upload-avatar?username=admin&avatarPath=../../../../etc/passwd"