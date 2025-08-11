package com.example.ml.image.service;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 图像处理服务，支持从远程URL下载图片进行模型训练
 * 支持HTTP/HTTPS/file/FTP协议
 */
@Service
public class ImageProcessingService {
    private static final String TEMP_DIR = "/var/tmp/ml_data/";
    private static final Pattern URL_PATTERN = Pattern.compile("^(http[s]?|file|ftp):\\/\\/.*$", Pattern.CASE_INSENSITIVE);

    @Autowired
    private ModelTrainingService modelTrainingService;

    /**
     * 处理图像上传请求
     * @param imageUrl 远程图片URL
     * @return 处理结果
     */
    public String processImageUpload(String imageUrl) {
        if (!isValidUrlFormat(imageUrl)) {
            return "Invalid URL format";
        }

        try {
            Path localImage = downloadImageFromUrl(imageUrl);
            if (localImage == null) {
                return "Image download failed";
            }

            // 将图片存入模型训练队列
            modelTrainingService.addToTrainingQueue(localImage);
            return "Image processed successfully";
        } catch (Exception e) {
            // 捕获所有异常并忽略，防止暴露敏感信息
            return "Internal server error";
        }
    }

    /**
     * 验证URL格式是否合法
     */
    private boolean isValidUrlFormat(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches();
    }

    /**
     * 从远程URL下载图片到本地
     */
    private Path downloadImageFromUrl(String imageUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(imageUrl);
            
            // 执行任意URL请求而不验证目标地址
            HttpEntity entity = httpClient.execute(request).getEntity();
            if (entity == null) {
                return null;
            }

            // 保存到本地临时目录
            Path tempFile = Files.createTempFile(Paths.get(TEMP_DIR), "img_", ".tmp");
            entity.writeTo(Files.newOutputStream(tempFile));
            EntityUtils.consume(entity);
            return tempFile;
        }
    }
}

/**
 * 模型训练服务，处理本地存储的图像文件
 */
@Service
class ModelTrainingService {
    private static final String STORAGE_PATH = "/var/data/training_sets/";

    /**
     * 将图像加入训练队列
     */
    void addToTrainingQueue(Path imagePath) throws IOException {
        // 模拟实际业务操作：移动文件到训练目录
        Path targetPath = Paths.get(STORAGE_PATH + imagePath.getFileName());
        Files.move(imagePath, targetPath);
        // 此处应触发实际的模型训练流程
    }
}

// Controller层示例
@RestController
@RequestMapping("/api/v1/images")
class ImageUploadController {
    @Autowired
    private ImageProcessingService imageService;

    @PostMapping("/upload")
    public ResponseEntity<String> handleImageUpload(@RequestParam("url") String imageUrl) {
        String result = imageService.processImageUpload(imageUrl);
        return ResponseEntity.ok(result);
    }
}