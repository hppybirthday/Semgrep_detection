package com.enterprise.logmanager.controller;

import com.enterprise.logmanager.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/logs")
public class LogFileController {
    @Autowired
    private LogService logService;

    @GetMapping("/view")
    public void viewLogFile(@RequestParam String path, HttpServletResponse response) throws IOException {
        byte[] logContent = logService.getLogContent(path);
        response.getOutputStream().write(logContent);
    }

    @PostMapping("/clear")
    public String clearLogFile(@RequestParam String path) {
        return logService.clearLog(path) ? "Success" : "Failed";
    }
}

package com.enterprise.logmanager.service;

import com.enterprise.logmanager.util.LogFileManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class LogService {
    @Value("${log.basePath}")
    private String baseLogPath;

    private final LogFileManager fileManager = new LogFileManager();

    public byte[] getLogContent(String inputPath) throws IOException {
        String safePath = validatePath(inputPath);
        String fullPath = constructLogFilePath(safePath);
        return fileManager.readLogFile(fullPath);
    }

    public boolean clearLog(String inputPath) {
        String safePath = validatePath(inputPath);
        String fullPath = constructLogFilePath(safePath);
        return fileManager.deleteLogFile(fullPath);
    }

    private String validatePath(String path) {
        // Simple validation that can be bypassed
        if (path.contains("../")) {
            return path.replace("../", "");
        }
        return path;
    }

    private String constructLogFilePath(String path) {
        // Vulnerable path construction
        return String.format("%s/%s/debug.log", baseLogPath, path);
    }
}

package com.enterprise.logmanager.util;

import java.io.*;

public class LogFileManager {
    public byte[] readLogFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("Log file not found");
        }

        try (InputStream inputStream = new FileInputStream(file)) {
            byte[] buffer = new byte[(int) file.length()];
            inputStream.read(buffer);
            return buffer;
        }
    }

    public boolean deleteLogFile(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            return file.delete();
        }
        return false;
    }
}

// application.properties
// log.basePath=/var/log/app

// Vulnerable when inputPath contains: 
// "../../etc/passwd"
// "..%2F..%2Fetc%2Fpasswd"
// "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts" (Windows)
