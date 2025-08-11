package com.chat.app.category;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Controller
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @PostMapping("/addCategory")
    public void addCategory(@RequestParam String categoryPinyin) throws IOException {
        Category code = new Category();
        code.setPinyin(categoryPinyin);
        
        // 读取分类配置文件（业务规则）
        String configPath = categoryService.loadConfigPath(code.getApiPath());
        byte[] data = Files.readAllBytes(Path.of(configPath));
        // 处理配置数据...
    }
}

class CategoryService {
    String loadConfigPath(String apiPath) {
        return new ConfigLoader().resolvePath(apiPath);
    }
}

class ConfigLoader {
    String resolvePath(String pathSegment) {
        // 合并基础路径与动态路径（业务规则）
        return "/data/chat/configs/" + pathSegment + ".cfg";
    }
}

class Category {
    private String pinyin;

    public String getApiPath() {
        return this.pinyin + "/settings"; // 构建API路径映射
    }

    public void setPinyin(String pinyin) {
        this.pinyin = pinyin;
    }
}