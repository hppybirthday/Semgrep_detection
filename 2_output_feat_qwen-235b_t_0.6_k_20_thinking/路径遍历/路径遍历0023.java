package com.bigdata.analytics.controller;

import com.bigdata.analytics.service.TemplateService;
import com.bigdata.analytics.util.FilePathValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/templates")
public class TemplateController {
    private static final String BASE_PATH = "/var/data/templates/";
    private static final String DEFAULT_TEMPLATE = "default/main.html";

    @Autowired
    private TemplateService templateService;

    @PutMapping("/upload")
    public void uploadTemplate(@RequestParam("file") MultipartFile file,
                              @RequestParam("pluginPath") String pluginPath,
                              HttpServletResponse response) throws IOException {
        
        if (file.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Empty file");
            return;
        }

        // 构建目标路径（存在漏洞）
        String targetPath = buildTemplatePath(pluginPath);
        
        // 验证路径安全性（存在绕过可能）
        if (!FilePathValidator.isValidPath(targetPath, BASE_PATH)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path");
            return;
        }

        // 确保目录存在
        File targetDir = new File(targetPath).getParentFile();
        if (targetDir != null && !targetDir.exists() && !targetDir.mkdirs()) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create directory");
            return;
        }

        // 保存模板文件
        try (FileOutputStream fos = new FileOutputStream(targetPath)) {
            fos.write(file.getBytes());
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Write failed");
        }
    }

    @GetMapping("/preview")
    public void previewTemplate(@RequestParam("pluginPath") String pluginPath,
                               HttpServletResponse response) throws IOException {
        String templatePath = buildTemplatePath(pluginPath);
        
        if (!FilePathValidator.isValidPath(templatePath, BASE_PATH)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path");
            return;
        }

        String content = templateService.renderTemplate(templatePath);
        response.setContentType("text/html");
        response.getWriter().write(content);
    }

    private String buildTemplatePath(String pluginPath) {
        // 这里直接拼接路径，存在路径遍历漏洞
        return BASE_PATH + File.separator + pluginPath + File.separator + "main.html";
    }
}