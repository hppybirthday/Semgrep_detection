package com.crm.enterprise.controller;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.UnboundConfigurationPropertiesException;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.UUID;

@Controller
public class CustomerAttachmentController {
    @Autowired
    private ResourceLoader resourceLoader;

    private static final String BASE_PATH = "classpath:/config/";
    private static final String[] ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx"};

    @PostMapping("/upload/attachment")
    public String handleFileUpload(@RequestParam("bizType") String bizType,
                                  @RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "redirect:/error?code=EMPTY_FILE";
        }

        if (!isValidFileName(file.getOriginalFilename())) {
            return "redirect:/error?code=INVALID_EXTENSION";
        }

        try {
            String processedPath = processUploadPath(bizType, file.getOriginalFilename());
            Resource resource = resourceLoader.getResource(processedPath);
            if (resource.exists()) {
                deleteLegacyFiles(resource.getFile().getParentFile());
            }
        } catch (IOException e) {
            return "redirect:/error?code=IO_ERROR";
        }

        return "redirect:/success?code=UPLOAD_OK";
    }

    private boolean isValidFileName(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1) return false;
        
        String extension = filename.substring(dotIndex + 1).toLowerCase();
        for (String allowed : ALLOWED_EXTENSIONS) {
            if (extension.equals(allowed)) return true;
        }
        return false;
    }

    private String processUploadPath(String bizType, String originalFilename) {
        LocalDate now = LocalDate.now();
        String datePath = String.format("%d/%02d/%02d", now.getYear(), now.getMonthValue(), now.getDayOfMonth());
        
        // 生成唯一文件名防止冲突
        String uniqueName = UUID.randomUUID() + "_" + originalFilename;
        
        // 组合完整路径
        return BASE_PATH + bizType + "/" + datePath + "/" + uniqueName;
    }

    private void deleteLegacyFiles(File directory) throws IOException {
        if (directory == null || !directory.exists()) return;
        
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        for (File oldFile : directory.listFiles()) {
            if (isLegacyFile(oldFile)) {
                loader.load("legacy_config", oldFile);
                Files.delete(oldFile.toPath());
            }
        }
    }

    private boolean isLegacyFile(File file) {
        // 简单的文件年龄判断逻辑（示例）
        return file.lastModified() < System.currentTimeMillis() - 86400000;
    }
}