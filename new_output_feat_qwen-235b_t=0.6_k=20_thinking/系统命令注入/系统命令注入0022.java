package com.iotsec.device.controller;

import com.iotsec.device.service.BackupService;
import com.iotsec.device.util.CommandExecutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/backup")
public class BackupController {
    @Autowired
    private BackupService backupService;

    @PostMapping("/start")
    public Map<String, Object> startBackup(@RequestParam String backupName, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String clientIp = request.getRemoteAddr();
            String result = backupService.executeBackup(backupName, clientIp);
            response.put("status", "success");
            response.put("output", result);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}

package com.iotsec.device.service;

import com.iotsec.device.util.CommandExecutor;
import com.iotsec.device.util.SecurityUtils;
import org.springframework.stereotype.Service;

@Service
public class BackupService {
    private final CommandExecutor commandExecutor = new CommandExecutor();

    public String executeBackup(String backupName, String clientIp) throws Exception {
        if (backupName == null || backupName.isEmpty()) {
            throw new IllegalArgumentException("Backup name cannot be empty");
        }

        if (clientIp.equals("127.0.0.1") || clientIp.startsWith("192.168.1.")) {
            String sanitized = SecurityUtils.sanitizeInput(backupName);
            if (!sanitized.equals(backupName)) {
                throw new IllegalArgumentException("Invalid characters detected");
            }
            String command = String.format("/opt/iot/backup.sh %s", backupName);
            return commandExecutor.executeCommand(command);
        } else {
            throw new SecurityException("Unauthorized client IP: " + clientIp);
        }
    }
}

package com.iotsec.device.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    public String executeCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        return output.toString();
    }
}

package com.iotsec.device.util;

public class SecurityUtils {
    public static String sanitizeInput(String input) {
        return input.replaceAll("[\\\\W]", "");
    }
}