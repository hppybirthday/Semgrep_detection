package com.example.datacleaner.controller;

import com.example.datacleaner.service.CategoryService;
import com.example.datacleaner.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @PostMapping("/category/delete")
    public void deleteCategory(@RequestParam String categoryPinyin, HttpServletResponse response) {
        try {
            categoryService.deleteCategory(categoryPinyin);
            response.getWriter().write("Success");
        } catch (IOException e) {
            e.printStackTrace();
            response.setStatus(500);
        }
    }
}

package com.example.datacleaner.service;

import com.example.datacleaner.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class CategoryService {
    private final String BASE_DIR = "/var/datacleaner/categories";

    public void deleteCategory(String categoryPinyin) throws IOException {
        // 数据清洗步骤
        String sanitized = categoryPinyin.toLowerCase().replaceAll("[\\\\s\\\\W]+", "_");
        
        // 误认为经过清洗后路径安全
        if (FileUtil.isInvalidPath(sanitized)) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // 实际存在路径遍历漏洞
        FileUtil.deleteCategoryFile(BASE_DIR, sanitized);
    }
}

package com.example.datacleaner.util;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class FileUtil {
    public static boolean isInvalidPath(String path) {
        // 误判的路径检查
        return path.contains("..") || path.startsWith("/");
    }

    public static void deleteCategoryFile(String baseDir, String categoryName) throws IOException {
        // 漏洞点：用户输入被直接拼接
        File file = new File(baseDir + File.separator + categoryName + ".txt");
        
        // 看似安全的检查实际被绕过
        if (!file.getAbsolutePath().startsWith(baseDir)) {
            throw new SecurityException("Access denied");
        }
        
        // 当用户输入包含../时，实际删除任意文件
        if (file.exists()) {
            FileUtils.deleteQuietly(file);
        }
    }
}

// 漏洞利用示例：
// categoryPinyin参数传入"../../../../../tmp/evil"将删除/tmp/evil.txt
// 通过../绕过检查，因为baseDir检查在规范化路径前进行
// 实际file.getAbsolutePath()会解析路径，导致超出限制目录