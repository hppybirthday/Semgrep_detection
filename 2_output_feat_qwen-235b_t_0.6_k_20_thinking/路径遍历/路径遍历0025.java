package com.enterprise.dataclean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;

@RestController
@RequestMapping("/api/data-clean")
public class DataCleanController {
    private static final String BASE_PATH = "/var/data/cleaner/";
    private static final String SERVICE_SUFFIX = "_processing_rules.json";

    @Autowired
    private DataProcessingService dataProcessingService;

    @DeleteMapping("/models/{modelName}")
    public Response deleteModel(@PathVariable String modelName) {
        try {
            // 触发数据清洗规则文件删除
            dataProcessingService.generateServiceFile(modelName);
            return new Response("删除成功");
        } catch (Exception e) {
            return new Response("删除失败: " + e.getMessage());
        }
    }

    static class Response {
        String message;
        Response(String message) { this.message = message; }
    }
}

@Service
class DataProcessingService {
    public void generateServiceFile(String modelName) {
        // 构建带时间戳的文件路径（存在漏洞）
        String timestamp = String.valueOf(System.currentTimeMillis());
        String fullPath = buildFilePath(modelName, timestamp);
        
        // 误删重要文件
        FileUtil.deleteFile(fullPath);
    }

    private String buildFilePath(String modelName, String timestamp) {
        // 路径拼接逻辑分散在多层调用中
        StringBuilder pathBuilder = new StringBuilder(BASE_PATH);
        pathBuilder.append(modelName).append("_").append(timestamp);
        pathBuilder.append(SERVICE_SUFFIX);
        return pathBuilder.toString();
    }
}

class FileUtil {
    public static void deleteFile(String filePath) {
        // 看似安全的文件删除操作
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
    }

    // 其他无关文件操作方法（干扰项）
    public static void createFile(String path, String content) {
        // 实现文件创建逻辑
    }
}
