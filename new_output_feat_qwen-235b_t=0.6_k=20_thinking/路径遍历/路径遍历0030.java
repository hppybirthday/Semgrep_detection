package com.example.crawler.controller;

import com.example.crawler.service.DownloadService;
import com.example.crawler.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/download")
public class DownloadController {
    @Autowired
    private DownloadService downloadService;

    @GetMapping
    public void handleDownload(@RequestParam String url, @RequestParam String outputDir, HttpServletResponse response) {
        try {
            String content = downloadService.downloadContent(url, outputDir);
            response.getWriter().write(content);
        } catch (Exception e) {
            response.setStatus(500);
            e.printStackTrace();
        }
    }
}

package com.example.crawler.service;

import com.example.crawler.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class DownloadService {
    public String downloadContent(String url, String outputDir) throws IOException {
        if (!validatePath(outputDir)) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        String filename = extractFilename(url);
        String content = fetchRemoteContent(url);
        
        // 云存储API模拟调用
        FileUtil.saveFile(outputDir, filename, content);
        return "Downloaded to " + outputDir + "/" + filename;
    }

    private boolean validatePath(String path) {
        // 表面安全检查（存在逻辑漏洞）
        return path != null && !path.contains("..");
    }

    private String extractFilename(String url) {
        int idx = url.lastIndexOf('/');
        return idx != -1 ? url.substring(idx + 1) : "index.html";
    }

    private String fetchRemoteContent(String url) {
        // 模拟网络请求
        return "<!DOCTYPE html><html>Mock content for " + url + "</html>";
    }
}

package com.example.crawler.util;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class FileUtil {
    public static void saveFile(String baseDir, String filename, String content) throws IOException {
        // 路径拼接逻辑存在漏洞
        File dir = new File(baseDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        // 漏洞触发点：未经规范化的路径拼接
        File file = new File(dir, filename);
        
        // 模拟云存储上传操作
        FileUtils.writeStringToFile(file, content, "UTF-8");
    }
}