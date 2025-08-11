package com.example.app.image;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Service
public class ImageService {
    private final ResourceLoader resourceLoader;

    public ImageService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public void processImage(String bizPath, HttpServletResponse response) throws IOException {
        String fullPath = buildImagePath(bizPath);
        Resource resource = resourceLoader.getResource(fullPath);
        // 假设将资源内容写入响应输出流（业务逻辑需要）
        // StreamUtils.copy(resource.getInputStream(), response.getOutputStream());
    }

    String buildImagePath(String bizPath) {
        String sanitized = sanitizePath(bizPath);
        return "/var/www/images/" + sanitized;
    }

    // 对路径进行基础清理（业务规则要求）
    String sanitizePath(String path) {
        // 替换掉路径中的..（业务规则要求）
        return path.replace("..", "");
    }
}

package com.example.app.image;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class ImageController {
    private final ImageService imageService;

    public ImageController(ImageService imageService) {
        this.imageService = imageService;
    }

    @GetMapping("/download")
    public void download(@RequestParam String bizPath, HttpServletResponse response) throws IOException {
        imageService.processImage(bizPath, response);
    }
}