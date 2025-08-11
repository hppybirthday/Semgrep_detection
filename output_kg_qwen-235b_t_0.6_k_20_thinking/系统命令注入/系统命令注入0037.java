package org.example.app.controller;

import org.example.app.service.FileProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileProcessingResource {
    @Autowired
    private FileProcessingService fileProcessingService;

    @GetMapping("/compress/{filePath}")
    public String compressFile(@PathVariable String filePath) throws IOException {
        return fileProcessingService.compressLogFile(filePath);
    }
}

package org.example.app.service;

import org.example.app.infrastructure.CommandExecutor;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class FileProcessingService {
    private final CommandExecutor commandExecutor;

    public FileProcessingService(CommandExecutor commandExecutor) {
        this.commandExecutor = commandExecutor;
    }

    public String compressLogFile(String filePath) throws IOException {
        // 构造压缩命令（漏洞点：直接拼接用户输入）
        String[] command = {"tar", "-czf", "archive.tar.gz", filePath};
        return commandExecutor.executeCommand(command);
    }
}

package org.example.app.infrastructure;

import lombok.extern.slf4j.Slf4j;

import java.io.*;

@Slf4j
public class CommandExecutor {
    public String executeCommand(String[] command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
                log.info("Command output: {}", line);
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Command execution failed with exit code " + exitCode);
            }
            
            return result.toString();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
    }
}