package com.gamestudio.core.domain.category;

import com.gamestudio.config.FileStorageConfig;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

public class CategoryService {
    private final FileStorageConfig storageConfig;

    public CategoryService(FileStorageConfig storageConfig) {
        this.storageConfig = storageConfig;
    }

    public void saveCategoryData(String categoryId, String bizPath, String content) throws IOException {
        // 漏洞点：直接拼接用户输入的bizPath
        String fullPath = storageConfig.getUploadPath() + File.separator 
                         + bizPath + File.separator + categoryId + ".json";
        
        File file = new File(fullPath);
        
        // 创建父目录（可能创建任意路径）
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}

// 配置类
package com.gamestudio.config;

import lombok.Getter;
import java.nio.file.Paths;

@Getter
public class FileStorageConfig {
    private final String uploadPath;

    public FileStorageConfig(String baseDir) {
        // 基础路径设置（预期限制在此目录）
        this.uploadPath = Paths.get(baseDir, "game_data").toString();
    }
}

// 控制器层
package com.gamestudio.adapter.http;

import com.gamestudio.core.domain.category.CategoryService;
import java.io.IOException;
import java.util.Map;
import spark.Request;
import spark.Response;

public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    public String updateCategory(Request request, Response response) {
        try {
            Map<String, Object> params = request.queryParams();
            String categoryId = request.params("id");
            String bizPath = request.queryParams("path"); // 接收用户输入路径
            String content = request.body();
            
            categoryService.saveCategoryData(categoryId, bizPath, content);
            return "{\\"status\\":\\"success\\"}";
        } catch (IOException e) {
            response.status(500);
            return "{\\"error\\":\\"" + e.getMessage() + "\\"}";
        }
    }
}

// 领域实体
package com.gamestudio.core.domain.category;

import java.util.UUID;

public class Category {
    private final String id;
    private final String name;

    public Category(String name) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}