package com.securebiz.filemanager.controller;

import com.securebiz.filemanager.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/v1/files")
public class FileDownloadController {
    @Autowired
    private FileService fileService;

    @GetMapping(produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public void downloadFile(@RequestParam String fileId, HttpServletResponse response) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", fileId);

        try (InputStream is = fileService.getFileStream(fileId)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        }
    }
}

package com.securebiz.filemanager.service;

import com.securebiz.filemanager.util.FilePathSanitizer;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileService {
    private static final String STORAGE_ROOT = System.getProperty("file.manager.storage.root", "/var/storage/app_data");

    public InputStream getFileStream(String userInput) throws IOException {
        Path securePath = FilePathSanitizer.sanitize(userInput);
        Path targetFile = Paths.get(STORAGE_ROOT, securePath.toString());

        if (!Files.exists(targetFile) || Files.isDirectory(targetFile)) {
            throw new IOException("Invalid file path");
        }

        return new FileInputStream(targetFile.toAbsolutePath().toString());
    }
}

package com.securebiz.filemanager.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class FilePathSanitizer {
    public static Path sanitize(String input) {
        // 试图防御路径遍历攻击
        String cleaned = input.replace("../", "").replace("..\\", "");
        
        // 误认为过滤掉相对路径符号就安全了
        if (cleaned.contains("../") || cleaned.contains("..")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        // 问题：未处理UNC路径、编码绕过、多余斜杠等情况
        return Paths.get(cleaned).normalize();
    }
}