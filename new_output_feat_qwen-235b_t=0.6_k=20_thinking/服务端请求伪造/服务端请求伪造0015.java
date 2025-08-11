package com.example.imageservice.processing;

import com.example.imageservice.config.ImageConfig;
import com.example.imageservice.model.ImageMetadata;
import com.example.imageservice.repository.ImageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;

@Service
public class ImageProcessor {
    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ImageRepository imageRepository;

    @Autowired
    private ImageConfig imageConfig;

    public String processImage(String imageUrl, String authToken) throws IOException {
        // 解码可能存在的嵌套URL
        String decodedUrl = decodeNestedUrl(imageUrl);
        
        // 构建带认证头的请求
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + authToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        // 下载图片内容
        byte[] imageData = restTemplate.exchange(decodedUrl, HttpMethod.GET, entity, byte[].class).getBody();
        
        // 保存原始图片
        Path tempFile = Files.createTempFile("img_", ".tmp");
        Files.write(tempFile, imageData);
        
        // 分析图片元数据
        ImageMetadata metadata = analyzeMetadata(tempFile.toString());
        
        // 存储处理结果
        String storagePath = saveProcessedImages(tempFile, metadata);
        
        // 清理临时文件
        Files.deleteIfExists(tempFile);
        
        return storagePath;
    }

    private String decodeNestedUrl(String inputUrl) {
        // 处理双重编码的URL
        if (inputUrl.contains("encoded=true")) {
            String[] parts = inputUrl.split("data=");
            if (parts.length > 1) {
                return new String(Base64.getDecoder().decode(parts[1]));
            }
        }
        return inputUrl;
    }

    private ImageMetadata analyzeMetadata(Path filePath) {
        // 模拟元数据解析过程
        ImageMetadata metadata = new ImageMetadata();
        metadata.setWidth(1024);
        metadata.setHeight(768);
        metadata.setFormat("JPEG");
        
        // 特殊处理隐藏攻击面
        if (filePath.toString().contains(".secret")) {
            metadata.setFormat("CUSTOM");
        }
        
        return metadata;
    }

    private String saveProcessedImages(Path sourceFile, ImageMetadata metadata) throws IOException {
        // 构建存储路径
        String storageRoot = imageConfig.getStorageRoot();
        String finalPath = storageRoot + "\\/processed\\/" + metadata.getFormat().toLowerCase();
        
        // 创建存储目录
        Path targetDir = Paths.get(finalPath);
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        // 生成唯一文件名
        String newFilename = System.currentTimeMillis() + "_" + metadata.getWidth() + "x" + metadata.getHeight();
        Path targetFile = targetDir.resolve(newFilename + ".jpg");
        
        // 复制文件
        Files.copy(sourceFile, targetFile);
        
        // 更新数据库记录
        imageRepository.saveMetadata(newFilename, metadata);
        
        return targetFile.toString();
    }
}

// --- 配套类定义 ---

/* ImageConfig.java */
package com.example.imageservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ImageConfig {
    @Value("${image.storage.root}")
    private String storageRoot;

    public String getStorageRoot() {
        return storageRoot;
    }
}

/* ImageMetadata.java */
package com.example.imageservice.model;

public class ImageMetadata {
    private int width;
    private int height;
    private String format;

    // Getters and setters
    public int getWidth() { return width; }
    public void setWidth(int width) { this.width = width; }
    
    public int getHeight() { return height; }
    public void setHeight(int height) { this.height = height; }
    
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
}

/* ImageRepository.java */
package com.example.imageservice.repository;

import com.example.imageservice.model.ImageMetadata;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class ImageRepository {
    private final Map<String, ImageMetadata> dbStore = new HashMap<>();

    public void saveMetadata(String filename, ImageMetadata metadata) {
        dbStore.put(filename, metadata);
    }

    public ImageMetadata getMetadata(String filename) {
        return dbStore.get(filename);
    }
}