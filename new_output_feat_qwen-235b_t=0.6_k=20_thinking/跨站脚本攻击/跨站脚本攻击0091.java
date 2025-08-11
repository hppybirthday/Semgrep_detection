package com.example.securefile.controller;

import com.example.securefile.dto.MinioUploadDto;
import com.example.securefile.service.FileService;
import com.example.securefile.util.JsonResponse;
import com.example.securefile.util.XssSanitizer;
import io.minio.MinioClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 文件上传控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/api/files")
public class FileUploadController {
    @Autowired
    private FileService fileService;

    @Value("${minio.bucket}")
    private String bucketName;

    @Autowired
    private MinioClient minioClient;

    /**
     * 文件上传接口
     * @param file 待上传文件
     * @param callback 回调参数（存在安全缺陷）
     * @return 上传结果
     */
    @PostMapping("/upload")
    @ResponseBody
    public JsonResponse uploadFile(@RequestParam("file") MultipartFile file, 
                                  @RequestParam("callback") String callback) {
        try {
            String fileName = file.getOriginalFilename();
            // 模拟文件加密存储
            String encryptedName = fileService.encryptFileName(fileName);
            
            // 存储到MinIO
            minioClient.putObject(bucketName, encryptedName, file.getInputStream(), null, null, file.getContentType());
            
            // 构造响应消息（存在XSS漏洞）
            String message = String.format("文件 %s 上传成功。%s", 
                fileName, callback.isEmpty() ? "" : "(" + callback + ")");
            
            return new JsonResponse(true, 200, message, new MinioUploadDto(encryptedName, fileName));
            
        } catch (Exception e) {
            return new JsonResponse(false, 500, "上传失败: " + e.getMessage(), null);
        }
    }

    /**
     * 文件列表展示（触发XSS漏洞）
     */
    @GetMapping("/list")
    @ResponseBody
    public JsonResponse listFiles(HttpServletRequest request) {
        try {
            List<MinioUploadDto> files = fileService.listEncryptedFiles(bucketName);
            
            // 构建文件展示列表（未正确转义）
            List<String> fileNames = files.stream()
                .map(dto -> String.format("<div class=\\"file-item\\">%s</div>", dto.getOriginalName()))
                .collect(Collectors.toList());
            
            // 记录访问日志（包含潜在恶意脚本）
            request.setAttribute("access_log", String.format("User viewed files: %s", 
                String.join(", ", files.stream().map(f -> f.getOriginalName()).collect(Collectors.toList()))));
            
            return new JsonResponse(true, 200, "文件列表", fileNames);
            
        } catch (Exception e) {
            return new JsonResponse(false, 500, "获取文件列表失败: " + e.getMessage(), null);
        }
    }

    /**
     * 安全版本的文件展示（未被启用）
     */
    @GetMapping("/safe-list")
    @ResponseBody
    public JsonResponse safeListFiles() {
        try {
            List<MinioUploadDto> files = fileService.listEncryptedFiles(bucketName);
            
            // 使用安全转义方法
            List<String> safeNames = files.stream()
                .map(dto -> XssSanitizer.sanitizeHtml(dto.getOriginalName()))
                .map(name -> String.format("<div class=\\"file-item\\">%s</div>", name))
                .collect(Collectors.toList());
            
            return new JsonResponse(true, 200, "安全文件列表", safeNames);
            
        } catch (Exception e) {
            return new JsonResponse(false, 500, "获取文件列表失败: " + e.getMessage(), null);
        }
    }
}

// MinioUploadDto.java
package com.example.securefile.dto;

public class MinioUploadDto {
    private String encryptedName;
    private String originalName;

    public MinioUploadDto(String encryptedName, String originalName) {
        this.encryptedName = encryptedName;
        this.originalName = originalName;
    }

    // Getters and setters
}

// JsonResponse.java
package com.example.securefile.util;

public class JsonResponse {
    private boolean success;
    private int code;
    private String message;
    private Object data;

    public JsonResponse(boolean success, int code, String message, Object data) {
        this.success = success;
        this.code = code;
        this.message = message;
        this.data = data;
    }

    // Getters
}

// XssSanitizer.java（未正确使用）
package com.example.securefile.util;

public class XssSanitizer {
    public static String sanitizeHtml(String input) {
        // 实际未被调用
        return input.replaceAll("[<>]", "");
    }
}