package com.example.app.image;

import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.model.ObjectMetadata;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/messages")
public class MessageImageController {
    private final ImageUploadService imageUploadService;

    public MessageImageController(ImageUploadService imageUploadService) {
        this.imageUploadService = imageUploadService;
    }

    @PostMapping("/upload")
    public String uploadImage(@RequestParam String fileName, @RequestBody byte[] imageData) {
        try {
            return imageUploadService.uploadUserImage(fileName, imageData);
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    @GetMapping("/image/{fileName}")
    public void getImage(@PathVariable String fileName, HttpServletResponse response) throws IOException {
        byte[] imageData = imageUploadService.getImage(fileName);
        if (imageData != null) {
            response.getOutputStream().write(imageData);
        } else {
            response.sendError(404, "Image not found");
        }
    }
}

@Service
class ImageUploadService {
    @Value("${oss.bucket}")
    private String bucketName;
    @Value("${oss.endpoint}")
    private String endpoint;
    @Value("${oss.accessKeyId}")
    private String accessKeyId;
    @Value("${oss.secretAccessKey}")
    private String secretAccessKey;

    private final PathSanitizer pathSanitizer = new PathSanitizer();

    String uploadUserImage(String fileName, byte[] imageData) {
        if (!isValidImageExtension(fileName)) {
            return "Invalid file type";
        }

        String safePath = pathSanitizer.sanitize(fileName);
        OSS ossClient = new OSSClientBuilder().build(endpoint, accessKeyId, secretAccessKey);
        
        try {
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(imageData.length);
            
            // Vulnerable path construction here
            String objectKey = "user_images/" + safePath;
            
            ossClient.putObject(bucketName, objectKey, 
                new ByteArrayInputStream(imageData), metadata);
            
            return "Upload successful to " + objectKey;
        } finally {
            ossClient.shutdown();
        }
    }

    byte[] getImage(String fileName) {
        OSS ossClient = new OSSClientBuilder().build(endpoint, accessKeyId, secretAccessKey);
        try {
            String safePath = pathSanitizer.sanitize(fileName);
            // Vulnerable path usage here
            return ossClient.getObject(bucketName, "user_images/" + safePath)
                .getObjectContent().readStream().readAllBytes();
        } catch (Exception e) {
            return null;
        } finally {
            ossClient.shutdown();
        }
    }

    private boolean isValidImageExtension(String fileName) {
        return fileName.matches(".*\\.(jpg|jpeg|png|gif)$");
    }
}

class PathSanitizer {
    // Misleading security check with incomplete sanitization
    String sanitize(String input) {
        // Attempt to remove path traversal sequences (bypassable)
        String result = input.replaceAll("(\\\\.\\\\.\\\\/|\\\\.\\\\.)", "");
        
        // Additional validation that can be bypassed
        if (result.contains("/")) {
            throw new IllegalArgumentException("Nested paths not allowed");
        }
        
        return result;
    }
}