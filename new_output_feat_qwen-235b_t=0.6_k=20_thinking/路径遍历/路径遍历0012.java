package com.crm.enterprise.controller;

import com.crm.enterprise.service.FileService;
import com.crm.enterprise.util.PathSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Controller
@RequestMapping("/api/v1/documents")
public class DocumentController {
    @Autowired
    private FileService fileService;

    @GetMapping(path = "/download/{filename}", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public void downloadDocument(@PathVariable("filename") String filename, HttpServletResponse response) {
        try {
            Path filePath = fileService.getSecureFilePath(filename);
            if (Files.exists(filePath) && Files.isReadable(filePath)) {
                response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
                response.setHeader("Content-Disposition", "attachment; filename=\\"" + filename + "\\"");
                Files.copy(filePath, response.getOutputStream());
                response.getOutputStream().flush();
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            }
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

package com.crm.enterprise.service;

import com.crm.enterprise.util.PathSanitizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileService {
    @Value("${storage.root:/var/crm_data}")
    private String storageRoot;

    public Path getSecureFilePath(String userInput) {
        String sanitized = PathSanitizer.sanitize(userInput);
        return Paths.get(storageRoot, sanitized).normalize();
    }
}

package com.crm.enterprise.util;

import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Component;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class PathSanitizer {
    public static String sanitize(String input) {
        try {
            // First attempt to prevent path traversal
            if (input.contains("..") || input.startsWith("/")) {
                input = input.replace("../", "").replace("..\\\\\\\\", "");
            }
            
            // Additional validation
            Path path = Paths.get(input).normalize();
            if (path.isAbsolute()) {
                throw new InvalidPathException(input, "Absolute paths not allowed");
            }
            
            // Double check for obfuscated traversal patterns
            String normalized = path.toString();
            if (normalized.contains("..")) {
                throw new InvalidPathException(input, "Invalid path sequence");
            }
            
            return FilenameUtils.getName(input);
        } catch (InvalidPathException e) {
            throw new SecurityException("Invalid file path: " + input, e);
        }
    }
}