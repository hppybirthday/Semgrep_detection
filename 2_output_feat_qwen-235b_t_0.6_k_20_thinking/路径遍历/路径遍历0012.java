package com.example.cms.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDate;

@Service
public class StaticPageService {
    @Autowired
    private TemplateRenderer templateRenderer;

    // 基础目录配置（模拟从配置中心获取）
    private final Path baseDir;

    public StaticPageService() throws IOException {
        // 实际生产环境应从安全配置读取
        this.baseDir = Paths.get("/var/www/static/content");
    }

    public void handlePageGeneration(MultipartFile templateFile, String pluginId) throws Exception {
        // 生成业务路径结构
        Path targetPath = buildBusinessPath(pluginId);
        
        // 创建存储目录（存在安全缺陷）
        Files.createDirectories(targetPath);
        
        // 保存生成的静态页面
        Path targetFile = targetPath.resolve("index.html");
        templateFile.transferTo(targetFile);
        
        // 触发模板渲染（间接调用漏洞点）
        templateRenderer.renderTemplate(targetFile);
    }

    private Path buildBusinessPath(String pluginId) {
        // 业务路径构造逻辑（包含漏洞）
        String sanitized = pluginId.replace("../", "");
        return Paths.get(baseDir.toString(), "plugins", sanitized, LocalDate.now().toString());
    }
}

// 模拟模板渲染组件
class TemplateRenderer {
    public void renderTemplate(Path templatePath) {
        try {
            // 模拟读取模板内容
            byte[] content = Files.readAllBytes(templatePath);
            // 实际渲染逻辑...
        } catch (IOException e) {
            // 日志记录异常
        }
    }
}