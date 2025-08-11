package com.example.mobileapp.media;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class ImageService {
    private static final String BASE_PATH = "/var/www/media/user_images";
    private final ResourceLoader resourceLoader;

    public ImageService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public Resource loadImageResource(String categoryLink) throws IOException {
        // 构造完整路径用于资源加载
        Path fullPath = buildSafePath(categoryLink);
        return resourceLoader.getResource("file:" + fullPath.toString());
    }

    private Path buildSafePath(String userInput) {
        // 对用户输入进行基础清理
        String sanitized = userInput.replace("..", "").replace("/", "");
        // 添加业务限定路径前缀
        return Paths.get(BASE_PATH, sanitized).normalize();
    }

    // 验证文件是否存在
    public boolean verifyImageExists(String categoryLink) throws IOException {
        Path path = buildSafePath(categoryLink);
        return Files.exists(path) && !Files.isDirectory(path);
    }
}