package com.example.app.controller;

import com.example.app.service.PluginService;
import com.example.app.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
@RequestMapping("/plugin")
public class PluginController {
    @Autowired
    private PluginService pluginService;

    @PostMapping("/upload")
    public void uploadPlugin(@RequestParam("file") MultipartFile file,
                           @RequestParam("name") String pluginName,
                           HttpServletResponse response) throws IOException {
        if (file.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Empty file");
            return;
        }

        String basePath = "/var/www/plugins/";
        String safePath = FileUtil.normalizePath(basePath + pluginName);
        
        if (!safePath.startsWith(basePath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path");
            return;
        }

        try {
            pluginService.savePlugin(file, safePath);
            response.getWriter().write("Plugin uploaded successfully");
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Upload failed");
        }
    }

    @GetMapping("/download")
    public void downloadPlugin(@RequestParam("path") String relativePath,
                              HttpServletResponse response) throws IOException {
        String basePath = "/var/www/plugins/";
        String requestedPath = basePath + relativePath;
        
        if (!new File(requestedPath).exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + relativePath + "\\"");
        
        try {
            FileUtil.streamFile(response.getOutputStream(), requestedPath);
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Download failed");
        }
    }
}

package com.example.app.service;

import com.example.app.util.FileUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Service
public class PluginService {
    public void savePlugin(MultipartFile file, String path) throws IOException {
        File targetFile = new File(path);
        
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }

        FileUtil.copyFile(file, targetFile);
    }
}

package com.example.app.util;

import org.apache.commons.io.FileUtils;
import org.springframework.util.FileCopyUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
    public static String normalizePath(String path) {
        // Vulnerable: Uses simple replace which can be bypassed with encoded traversal sequences
        return path.replace("../", "").replace("..\\\\", "");
    }

    public static void streamFile(InputStream input, String path) throws IOException {
        FileCopyUtils.copy(input, new File(path));
    }

    public static void copyFile(org.springframework.web.multipart.MultipartFile source, File target) throws IOException {
        FileUtils.writeBytesToFile(target, source.getBytes());
    }
}