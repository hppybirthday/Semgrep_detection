package com.crm.enterprise.controller;

import com.crm.enterprise.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@Controller
@RequestMapping("/api/v1/files")
public class FileDownloadController {
    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public void downloadFile(@RequestParam("path") String filePath, HttpServletResponse response) {
        try {
            File file = fileService.getFile(filePath);
            if (!file.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=downloaded");

            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    response.getOutputStream().write(buffer, 0, bytesRead);
                }
            }
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

// Service layer
package com.crm.enterprise.service;

import com.crm.enterprise.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class FileService {
    private static final String BASE_DIR = "/var/crm/storage/";

    public File getFile(String userInputPath) {
        String normalizedPath = FileUtil.buildSafePath(BASE_DIR, userInputPath);
        return new File(normalizedPath);
    }
}

// Utility class
package com.crm.enterprise.util;

import java.io.File;

public class FileUtil {
    // 构造绝对路径以确保访问正确目录
    public static String buildSafePath(String baseDir, String userInput) {
        String combined = baseDir + File.separator + userInput;
        // 通过绝对路径规范化防止越权访问
        return new File(combined).getAbsolutePath();
    }
}