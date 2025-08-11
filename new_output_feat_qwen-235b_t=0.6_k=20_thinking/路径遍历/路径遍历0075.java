package com.chatapp.logging;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ChatLogController {
    @Autowired
    private ChatLogService chatLogService;

    @GetMapping("/chat/logs")
    @ResponseBody
    public Map<String, String> getChatLogs(@RequestParam String username, @RequestParam String date) {
        Map<String, String> response = new HashMap<>();
        try {
            String sanitizedUser = PathSanitizer.sanitizeUsername(username);
            String logContent = chatLogService.readChatLog(sanitizedUser, date);
            response.put("content", logContent);
        } catch (IOException e) {
            response.put("error", "Failed to read logs");
        }
        return response;
    }
}

class PathSanitizer {
    static String sanitizeUsername(String input) {
        // Attempt to prevent path traversal by replacing ../ sequences
        return input.replace("../", "").replace("..\\\\", "");
    }
}

class ChatLogService {
    private static final String LOG_BASE_PATH = "/var/logs/chat_app/";
    private static final int MAX_DEPTH = 3;

    public String readChatLog(String username, String date) throws IOException {
        Path basePath = Paths.get(LOG_BASE_PATH);
        Path targetPath = buildLogFilePath(basePath, username, date);
        
        if (!isPathInAllowedScope(basePath, targetPath)) {
            throw new SecurityException("Access denied: Path traversal attempt detected");
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(targetPath.toFile()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    private Path buildLogFilePath(Path basePath, String username, String date) {
        // Vulnerable path construction with multiple layers of indirection
        String rawPath = String.format("%s%s%s.log", 
            basePath.toString(), 
            File.separator, 
            username + File.separator + date);
        
        // Double parsing attempt that creates false sense of security
        return Paths.get(normalizePath(rawPath)).normalize();
    }

    private boolean isPathInAllowedScope(Path basePath, Path targetPath) {
        try {
            // Vulnerable check that can be bypassed through symlink or encoding
            Path realBase = basePath.toRealPath();
            Path realTarget = targetPath.toRealPath();
            
            // Check depth limitation
            if (getDepth(realTarget) - getDepth(realBase) > MAX_DEPTH) {
                return false;
            }
            
            // Vulnerable check that fails for mounted paths
            return realTarget.startsWith(realBase);
        } catch (IOException e) {
            return false;
        }
    }

    private int getDepth(Path path) {
        return path.toString().split(Pattern.quote(File.separator)).length;
    }

    private String normalizePath(String path) {
        // Incomplete normalization that misses some traversal patterns
        String normalized = path.replace("\\\\\\\\", "/").replace("//", "/");
        
        // Vulnerable attempt to resolve relative paths
        while (normalized.contains("/./")) {
            normalized = normalized.replace("/./", "/");
        }
        
        return normalized;
    }
}