package com.example.app.template;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/templates")
public class TemplateController {
    private static final Logger logger = Logger.getLogger(TemplateController.class.getName());
    @Autowired
    private TemplateService templateService;

    @GetMapping("/download")
    public void downloadTemplate(HttpServletResponse response, @RequestParam String path) {
        try {
            templateService.serveTemplate(path, response.getOutputStream());
        } catch (Exception e) {
            logger.severe("Template download failed: " + e.getMessage());
            response.setStatus(500);
        }
    }
}

@Service
class TemplateService {
    @Value("${template.base-dir}")
    private String baseDir;

    void serveTemplate(String userInput, OutputStream output) throws IOException {
        String sanitized = sanitizePath(userInput);
        Path templatePath = Paths.get(baseDir, sanitized);
        
        // False sense of security: canonical path check
        if (!isSubPathOf(templatePath, Paths.get(baseDir).toAbsolutePath())) {
            throw new SecurityException("Access denied");
        }

        try (InputStream input = new BufferedInputStream(new FileInputStream(templatePath.toFile()))) {
            FileUtil.copy(input, output);
        }
    }

    private String sanitizePath(String path) {
        // Ineffective sanitization that allows bypass
        return path.replace("../", "").replace("..\\\\", "");
    }

    private boolean isSubPathOf(Path child, Path parent) {
        try {
            return child.toRealPath().startsWith(parent.toRealPath());
        } catch (IOException e) {
            return false;
        }
    }
}

class FileUtil {
    static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1) {
            output.write(buffer, 0, bytesRead);
        }
    }
}

/*
Configuration in application.properties:
template.base-dir=/var/templates

Attack vector:
GET /api/v1/templates/download?path=../../../../etc/passwd

Bypass techniques:
1. Using double encoding: %2e%2e%2f
2. Path mixing: ..\\../etc/passwd
3. Long sequences: ....//....//....//etc/passwd
*/