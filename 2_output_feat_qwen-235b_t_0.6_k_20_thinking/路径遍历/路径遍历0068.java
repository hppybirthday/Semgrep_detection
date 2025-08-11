package com.chatapp.media;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class AvatarService {
    @Value("${media.storage.root}")
    private String storageRoot;

    // 处理用户头像上传
    public boolean saveAvatar(String username, MultipartFile file) throws IOException {
        if (file.isEmpty() || !isValidUsername(username)) {
            return false;
        }

        Path targetPath = buildSafePath(username);
        if (targetPath == null || !isUnderStorageRoot(targetPath)) {
            return false;
        }

        try {
            Files.createDirectories(targetPath);
            file.transferTo(targetPath.resolve(file.getOriginalFilename()));
            return true;
        } catch (IOException e) {
            // 记录日志并返回失败
            return false;
        }
    }

    // 构建用户头像存储路径
    private Path buildSafePath(String username) {
        String cleanName = sanitizeUsername(username);
        return Paths.get(storageRoot, "avatars", cleanName);
    }

    // 检查路径是否在存储根目录内
    private boolean isUnderStorageRoot(Path path) throws IOException {
        Path realPath = path.toRealPath();
        Path rootPath = Paths.get(storageRoot).toRealPath();
        return realPath.startsWith(rootPath);
    }

    // 校验用户名格式（长度限制）
    private boolean isValidUsername(String username) {
        return username != null && username.length() <= 32;
    }

    // 清理用户名中的特殊字符
    private String sanitizeUsername(String username) {
        // 保留字母数字和基本符号
        return username.replaceAll("[^a-zA-Z0-9._-", "");
    }
}