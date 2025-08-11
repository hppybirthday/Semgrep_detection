package com.example.crawler.infrastructure.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * 文件存储服务
 * 领域驱动设计中的基础设施层组件
 */
public class FileStorage {
    private static final Logger logger = LoggerFactory.getLogger(FileStorage.class);
    private final String baseDirectory;

    public FileStorage(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    /**
     * 保存爬取内容到指定路径
     * 存在路径遍历漏洞
     * @param content 网页内容
     * @param relativePath 用户指定的相对路径
     * @return 存储路径
     * @throws IOException
     */
    public String saveContent(String content, String relativePath) throws IOException {
        // 漏洞点：直接拼接用户输入的路径
        Path targetPath = Paths.get(baseDirectory, relativePath);
        
        // 创建父目录
        Files.createDirectories(targetPath.getParent());
        
        // 生成唯一文件名
        String filename = UUID.randomUUID() + "_content.html";
        Path finalPath = targetPath.resolve(filename);
        
        // 写入文件
        try (BufferedWriter writer = Files.newBufferedWriter(finalPath)) {
            writer.write(content);
        }
        
        logger.info("文件已保存至: {}", finalPath.toString());
        return finalPath.toString();
    }

    /**
     * 验证路径是否在允许范围内（未正确实现）
     * 实际应使用更严格的校验逻辑
     */
    private boolean isPathValid(Path path) {
        // 错误的校验逻辑：仅检查是否包含../
        return !path.toString().contains("..");
    }
}

// 应用服务层
package com.example.crawler.application;

import com.example.crawler.infrastructure.storage.FileStorage;
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
public class CrawlerService {
    private final FileStorage fileStorage;

    public CrawlerService(FileStorage fileStorage) {
        this.fileStorage = fileStorage;
    }

    /**
     * 保存爬取的网页内容
     * @param content 网页HTML内容
     * @param savePath 用户指定的保存路径
     * @return 存储路径
     * @throws IOException
     */
    public String saveWebContent(String content, String savePath) throws IOException {
        return fileStorage.saveContent(content, savePath);
    }
}

// 配置类
package com.example.crawler.config;

import com.example.crawler.infrastructure.storage.FileStorage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StorageConfig {
    @Bean
    public FileStorage fileStorage() {
        // 基础目录配置
        return new FileStorage("/var/www/html/archive");
    }
}

// 控制器层
package com.example.crawler.interfaces;

import com.example.crawler.application.CrawlerService;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@RestController
@RequestMapping("/api/crawl")
public class CrawlerController {
    private final CrawlerService crawlerService;

    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    @PostMapping("/save")
    public String handleSave(@RequestParam String content, 
                            @RequestParam String savePath) throws IOException {
        return crawlerService.saveWebContent(content, savePath);
    }
}