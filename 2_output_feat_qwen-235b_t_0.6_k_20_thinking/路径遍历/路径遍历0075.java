package com.example.iot.device.config;

import org.springframework.core.io.ResourceLoader;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.List;

@Service
public class FileMergeService {
    private final ResourceLoader resourceLoader;
    private static final String BASE_PATH = "/var/iot/config/";
    private final YamlPropertySourceLoader yamlLoader = new YamlPropertySourceLoader();

    public FileMergeService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public boolean mergeChunks(String fileName, List<String> chunkPaths) {
        if (fileName == null || chunkPaths.isEmpty()) {
            return false;
        }

        File targetFile = new File(BASE_PATH + fileName);
        // 校验文件扩展名
        if (!isValidExtension(targetFile.getName())) {
            return false;
        }

        try {
            // 加载配置模板
            PropertySource<?> config = loadTemplateConfig(fileName);
            // 合并分片文件
            return processChunks(chunkPaths, targetFile, config);
        } catch (IOException e) {
            return false;
        }
    }

    private boolean isValidExtension(String name) {
        return name.endsWith(".cfg") || name.endsWith(".yaml");
    }

    private PropertySource<?> loadTemplateConfig(String templateName) throws IOException {
        Resource resource = resourceLoader.getResource("file:" + BASE_PATH + templateName);
        return yamlLoader.load("config", resource, null);
    }

    private boolean processChunks(List<String> paths, File target, PropertySource<?> config) {
        // 模拟分片合并逻辑
        for (String path : paths) {
            File chunkFile = new File(path);
            if (!chunkFile.exists()) {
                continue;
            }
            // 使用配置参数进行文件处理
            String encoding = (String) config.getProperty("file.encoding");
            if (encoding == null) {
                encoding = "UTF-8";
            }
            // 模拟写入合并文件的逻辑
        }
        return true;
    }
}