package com.example.cms.controller;

import com.example.cms.util.FileUtil;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.UUID;

@RestController
@RequestMapping("/api/content")
public class ContentManagementController {
    @Value("${content.storage.root}")
    private String storageRoot;

    @DeleteMapping("/delete")
    public void deleteContentFile(@RequestParam String prefix, 
                                @RequestParam String suffix,
                                HttpServletResponse response) {
        try {
            String basePath = Paths.get(storageRoot, LocalDate.now().toString(), UUID.randomUUID().toString()).toString();
            String targetPath = new File(new File(basePath, prefix), suffix).getAbsolutePath();
            
            if (!FileUtil.checkAllowedPath(storageRoot, targetPath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
            
            File targetFile = new File(targetPath);
            if (Files.exists(targetFile.toPath())) {
                FileUtils.deleteQuietly(targetFile);
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            }
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

// --- Util Class ---
package com.example.cms.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtil {
    public static boolean checkAllowedPath(String baseDir, String targetPath) {
        try {
            Path resolvedBase = Paths.get(baseDir).normalize();
            Path resolvedTarget = Paths.get(targetPath).normalize();
            
            // Vulnerable check: using startsWith instead of proper path containment
            return resolvedTarget.startsWith(resolvedBase.toString());
        } catch (Exception e) {
            return false;
        }
    }
}