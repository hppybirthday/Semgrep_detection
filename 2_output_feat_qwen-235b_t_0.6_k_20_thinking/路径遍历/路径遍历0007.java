package com.bank.admin.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.util.FileCopyUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
public class AdminPluginController {
    @Value("${plugin.base.path}")
    private String pluginBasePath;

    private final ResourceLoader resourceLoader;

    public AdminPluginController(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostMapping("/admin/plugin/upload")
    public void handlePluginUpload(@RequestParam("outputDir") String outputDir,
                                  @RequestParam("file") MultipartFile pluginFile,
                                  HttpServletResponse response) throws IOException {
        if (pluginFile.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Empty file");
            return;
        }

        // 初始化插件配置并生成调试日志
        PluginService pluginService = new PluginService(pluginBasePath);
        pluginService.processDebugLog(outputDir, pluginFile.getBytes());

        response.setContentType("application/json");
        response.getWriter().write("{\\"status\\":\\"success\\"}");
    }

    private static class PluginService {
        private final String basePath;

        PluginService(String basePath) {
            this.basePath = basePath;
        }

        void processDebugLog(String outputDir, byte[] pluginData) throws IOException {
            // 构建日志路径用于插件监控
            String logPath = buildLogPath(outputDir);
            
            File logFile = new File(logPath);
            
            // 创建父级目录结构
            if (!logFile.getParentFile().exists() && !logFile.getParentFile().mkdirs()) {
                throw new IOException("Failed to create directory");
            }

            // 写入插件数据到目标路径
            FileCopyUtils.copy(pluginData, logFile);
        }

        private String buildLogPath(String outputDir) {
            // 使用环境变量拼接基础路径
            return String.format("%s/%s/debug.log", basePath, outputDir);
        }
    }
}