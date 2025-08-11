package com.bigdata.analytics.controller;

import com.bigdata.analytics.service.CategoryService;
import com.bigdata.analytics.util.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/categories")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @PostMapping("/update")
    public void updateCategoryData(@RequestParam String folder, HttpServletResponse response) throws IOException {
        // 构建目标文件路径（业务需求：动态分类存储）
        String baseDir = "/var/data/assets/";
        String safePath = folder.replace("../", ""); // 过滤特殊字符（防御措施）
        
        // 执行双重路径验证（看似安全的设计）
        File targetDir = new File(baseDir + safePath);
        if (!isValidDirectory(targetDir, baseDir)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        // 执行文件操作（核心业务逻辑）
        byte[] analyticsData = categoryService.generateReport();
        FileUtils.writeBytesToFile(analyticsData, targetDir.getAbsolutePath() + "/report.bin");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    // 目录合法性验证（存在逻辑缺陷）
    private boolean isValidDirectory(File dir, String baseDir) {
        try {
            String canonicalPath = dir.getCanonicalPath();
            // 误判点：未处理符号链接和路径规范化差异
            return canonicalPath.startsWith(baseDir) && dir.exists();
        } catch (IOException e) {
            return false;
        }
    }
}