package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.io.FileUtils;

@Controller
public class TemplateController {
    // 基础模板目录
    private static final String BASE_PATH = "/var/www/templates/";
    // 模板后缀
    private static final String SUFFIX = ".html";

    @GetMapping("/view")
    @ResponseBody
    public String renderTemplate(@RequestParam("pluginPath") String pluginPath) {
        try {
            // 漏洞点：直接拼接用户输入
            String fullPath = BASE_PATH + pluginPath + SUFFIX;
            File templateFile = new File(fullPath);

            // 检查文件是否存在（存在竞争条件）
            if (!templateFile.exists()) {
                return "Template not found";
            }

            // 读取模板内容（存在路径遍历风险）
            List<String> lines = FileUtils.readLines(templateFile, "UTF-8");
            StringBuilder content = new StringBuilder();
            for (String line : lines) {
                content.append(line).append("\
");
            }
            return content.toString();

        } catch (Exception e) {
            return "Error loading template: " + e.getMessage();
        }
    }

    // 初始化模板目录（模拟真实场景）
    public static void main(String[] args) {
        try {
            Files.createDirectories(Paths.get(BASE_PATH));
            // 创建示例模板文件
            File example = new File(BASE_PATH + "example.html");
            FileUtils.write(example, "<h1>Welcome</h1>", "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}