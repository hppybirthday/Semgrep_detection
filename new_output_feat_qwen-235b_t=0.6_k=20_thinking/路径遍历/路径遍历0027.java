package com.mobileapp.logcenter.controller;

import com.mobileapp.logcenter.service.LogService;
import com.mobileapp.logcenter.util.PathUtils;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/logs")
public class LogDownloadController {
    
    @Value("${log.base.dir}")
    private String logBaseDir;

    private final LogService logService;

    public LogDownloadController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadLog(
            @RequestParam("appName") String appName,
            @RequestParam("logType") String logType,
            HttpServletResponse response) throws IOException {
        
        if (!PathUtils.isValidAppName(appName) || !PathUtils.isValidLogType(logType)) {
            return ResponseEntity.badRequest().build();
        }

        String safePath = PathUtils.constructSafePath(logBaseDir, appName, logType);
        
        if (!PathUtils.isPathUnderBaseDir(safePath, logBaseDir)) {
            return ResponseEntity.status(403).build();
        }

        File logFile = new File(safePath);
        if (!logFile.exists()) {
            return ResponseEntity.notFound().build();
        }

        byte[] fileContent = FileUtils.readFileToByteArray(logFile);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", logFile.getName());
        
        return ResponseEntity.ok().headers(headers).body(fileContent);
    }
}

package com.mobileapp.logcenter.util;

import java.nio.file.Paths;

public class PathUtils {
    
    public static boolean isValidAppName(String appName) {
        return appName != null && appName.matches("[a-zA-Z0-9_\\-]{3,30}");
    }

    public static boolean isValidLogType(String logType) {
        return logType != null && logType.matches("(error|access|audit|debug)");
    }

    public static String constructSafePath(String baseDir, String appName, String logType) {
        StringBuilder pathBuilder = new StringBuilder();
        pathBuilder.append(baseDir).append(File.separator)
                   .append(appName).append(File.separator)
                   .append("logs").append(File.separator)
                   .append(logType).append(".log");
        return pathBuilder.toString();
    }

    public static boolean isPathUnderBaseDir(String targetPath, String baseDir) {
        try {
            File baseFile = new File(baseDir);
            File targetFile = new File(targetPath);
            return targetFile.getCanonicalPath().startsWith(baseFile.getCanonicalPath());
        } catch (Exception e) {
            return false;
        }
    }
}

package com.mobileapp.logcenter.service;

import org.springframework.stereotype.Service;

@Service
public class LogService {
    
    public String getLogFilePath(String appName, String logType) {
        // Simulated database lookup
        if ("user-service".equals(appName) && "error".equals(logType)) {
            return "/var/logs/app/user-service/logs/error.log";
        }
        return null;
    }
}