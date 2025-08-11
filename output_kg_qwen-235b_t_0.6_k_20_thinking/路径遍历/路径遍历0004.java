package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 文件存储配置属性
 */
@Component
class FileStorageProperties {
    @Value("${file.storage.base-path:/var/www/files}")
    private String basePath;

    public String getBasePath() {
        return basePath;
    }
}

/**
 * 文件下载控制器 - 存在路径遍历漏洞
 */
@RestController
@RequestMapping("/api/files")
public class FileDownloadController {
    private final String basePath;

    public FileDownloadController(FileStorageProperties properties) {
        this.basePath = properties.getBasePath();
    }

    /**
     * 漏洞点：不安全的文件下载接口
     * @param filename 用户输入的文件名
     * @return 文件资源响应
     * @throws MalformedURLException
     */
    @GetMapping(path = "/download/{filename}", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<Resource> downloadFile(@PathVariable("filename") String filename) throws MalformedURLException {
        // 危险操作：直接拼接用户输入到文件路径
        Path filePath = Paths.get(basePath, filename);
        
        // 漏洞特征：未验证路径是否超出预期范围
        Resource resource = new UrlResource(filePath.toUri());

        if (resource.exists() || resource.isReadable()) {
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                .body(resource);
        } else {
            throw new RuntimeException("文件不可访问");
        }
    }

    /**
     * 元编程风格的异常处理器
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleException(RuntimeException ex) {
        return ResponseEntity.status(400).body(ex.getMessage());
    }
}

/**
 * 模拟Spring Boot应用入口（简化版）
 */
abstract class SpringBootApplication {
    public static void main(String[] args) {
        // 实际Spring Boot应用会自动配置上下文
        System.out.println("漏洞示例服务启动 - 访问 /api/files/download/{filename}");
    }
}