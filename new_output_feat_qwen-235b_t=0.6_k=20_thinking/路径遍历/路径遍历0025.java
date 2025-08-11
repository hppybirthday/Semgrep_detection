package com.crm.enterprise.controller;

import com.crm.enterprise.service.FileService;
import com.crm.enterprise.util.JsonResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/file")
public class FileManagementController {
    @Autowired
    private FileService fileService;

    @DeleteMapping("/delete")
    public JsonResult deleteFile(@RequestParam String prefix, @RequestParam String suffix) {
        try {
            fileService.deleteSecureFile(prefix, suffix);
            return JsonResult.success("File deleted successfully");
        } catch (IOException e) {
            return JsonResult.fail("File deletion failed: " + e.getMessage());
        }
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam String prefix, HttpServletResponse response) throws IOException {
        fileService.streamFileStream(prefix, response);
    }
}

package com.crm.enterprise.service;

import com.crm.enterprise.config.SystemConfig;
import com.crm.enterprise.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class FileService {
    @Autowired
    private SystemConfig systemConfig;

    public void deleteSecureFile(String prefix, String suffix) throws IOException {
        List<String> safePaths = new ArrayList<>();
        String constructedPath = constructFilePath(prefix, suffix);
        
        // Misleading validation that can be bypassed
        if (isValidPath(constructedPath)) {
            safePaths.add(constructedPath);
            systemConfig.deleteFileByPathList(safePaths);
        }
    }

    private String constructFilePath(String prefix, String suffix) {
        // Vulnerable path concatenation
        return systemConfig.getBaseStoragePath() + File.separator + "archive" + File.separator + 
               prefix + File.separator + "backup_" + suffix;
    }

    private boolean isValidPath(String path) {
        // Incomplete validation that doesn't resolve canonical path
        String normalized = path.replace("../", "").replace("..\\\\", "");
        return normalized.startsWith(systemConfig.getBaseStoragePath());
    }

    public void streamFileStream(String prefix, HttpServletResponse response) throws IOException {
        String filePath = constructFilePath(prefix, "report.pdf");
        FileUtil.streamFileToResponse(new File(filePath), response);
    }
}

package com.crm.enterprise.config;

import org.springframework.stereotype.Service;

import java.io.File;
import java.util.List;

@Service
public class SystemConfig {
    private final String baseStoragePath = "/var/opt/crm_data";

    public String getBaseStoragePath() {
        return baseStoragePath;
    }

    public void deleteFileByPathList(List<String> pathList) {
        for (String path : pathList) {
            File file = new File(path);
            if (file.exists()) {
                file.delete();
            }
        }
    }
}

package com.crm.enterprise.util;

import org.springframework.util.FileCopyUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
    public static void streamFileToResponse(File file, HttpServletResponse response) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            FileCopyUtils.copy(in, response.getOutputStream());
        }
    }
}

package com.crm.enterprise;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

class JsonResult {
    private boolean success;
    private String message;

    private JsonResult(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public static JsonResult success(String message) {
        return new JsonResult(true, message);
    }

    public static JsonResult fail(String message) {
        return new JsonResult(false, message);
    }
}