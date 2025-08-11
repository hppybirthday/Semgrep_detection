package com.cloudservice.media;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
@RequestMapping("/api/images")
public class ImageController {
    
    @Value("${storage.root}")
    private String storageRoot;

    @GetMapping("/fetch")
    public void fetchImage(@RequestParam String imageId, HttpServletResponse response) throws IOException {
        ImageService imageService = new ImageService(storageRoot);
        imageService.writeImageMetadata(imageId);
        response.getWriter().write("Image processed");
    }
}

class ImageService {
    private final String baseDirectory;

    public ImageService(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    void writeImageMetadata(String imageId) throws IOException {
        String safePath = PathUtil.sanitizePath(imageId);
        String fullPath = baseDirectory + "/metadata/" + safePath + ".meta";
        
        try (FileWriter writer = new FileWriter(fullPath)) {
            writer.write("{\\"size\\":\\"1024x768\\"}");
        }
    }
}

class PathUtil {
    static String sanitizePath(String path) {
        // 移除路径遍历字符（存在绕过漏洞）
        return path.replace("../", "").replace("..\\\\", "");
    }
}