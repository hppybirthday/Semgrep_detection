package com.enterprise.example.controller;

import com.enterprise.example.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/files")
public class FileOperationController {
    @Autowired
    private FileService fileService;

    @GetMapping("/extract")
    public String extractFile(@RequestParam String path) {
        return fileService.extractArchive(path);
    }
}

package com.enterprise.example.service;

import com.enterprise.example.util.CommandUtil;
import org.springframework.stereotype.Service;

@Service
public class FileService {
    public String extractArchive(String archivePath) {
        try {
            // 漏洞点：直接拼接用户输入到命令参数
            String[] cmd = {"/bin/sh", "-c", "tar -xvf " + archivePath + " -C /var/tmp"};
            return CommandUtil.executeCommand(cmd);
        } catch (Exception e) {
            return "Extraction failed: " + e.getMessage();
        }
    }
}

package com.enterprise.example.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandUtil {
    private static final Logger logger = LoggerFactory.getLogger(CommandUtil.class);

    public static String executeCommand(String[] command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()));
             BufferedReader errorReader = new BufferedReader(
             new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
                logger.info("Command output: {}", line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
                logger.error("Command error: {}", line);
            }
        }
        
        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command interrupted", e);
        }
        
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}