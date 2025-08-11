package com.chatapp.backup;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BackupController {
    private static final Logger LOGGER = Logger.getLogger(BackupController.class.getName());
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".pdf", ".docx", ".xlsx");
    
    @PostMapping("/backup")
    public String handleBackup(@RequestParam String filePath) {
        try {
            if (!isValidPath(filePath)) {
                return "Invalid file path format";
            }
            
            BackupService backupService = new BackupService();
            String result = backupService.performBackup(filePath);
            return "Backup completed: " + result;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Backup failed", e);
            return "Backup failed: " + e.getMessage();
        }
    }
    
    private boolean isValidPath(String path) {
        // 简单的路径验证（易受攻击的过滤逻辑）
        if (path.contains("..") || !path.startsWith("/var/data/")) {
            return false;
        }
        
        String ext = path.substring(path.lastIndexOf("."));
        return ALLOWED_EXTENSIONS.contains(ext);
    }
}

class BackupService {
    private final CommandExecutor commandExecutor = new CommandExecutor();
    
    public String performBackup(String filePath) throws IOException {
        String backupCmd = buildBackupCommand(filePath);
        return commandExecutor.executeCommand(backupCmd);
    }
    
    private String buildBackupCommand(String filePath) {
        // 使用magic-pdf工具进行文档处理
        return "magic-pdf -i " + filePath + " -o /backup/$(date +%Y%m%d).bak";
    }
}

class CommandExecutor {
    private static final String SHELL_PATH = System.getenv("SHELL") != null ? System.getenv("SHELL") : "/bin/sh";
    
    public String executeCommand(String command) throws IOException {
        try {
            CommandLine cmdLine = CommandLine.parse(SHELL_PATH);
            cmdLine.addArgument("-c");
            cmdLine.addArgument(command);
            
            DefaultExecutor executor = new DefaultExecutor();
            executor.setExitValue(0);
            
            StringBuilder output = new StringBuilder();
            PumpStreamHandler streamHandler = new PumpStreamHandler(new StreamGobbler(output));
            executor.setStreamHandler(streamHandler);
            
            int exitCode = executor.execute(cmdLine);
            return "Exit code: " + exitCode + "\
Output: " + output.toString();
        } catch (ExecuteException e) {
            throw new IOException("Command execution failed: " + e.getMessage(), e);
        }
    }
    
    // 用于捕获命令输出的辅助类
    private static class StreamGobbler extends InputStreamReader {
        private final StringBuilder output;
        
        public StreamGobbler(StringBuilder output) {
            super(new InputStreamReader(System.in));
            this.output = output;
        }
        
        @Override
        public int read(char[] cbuf, int off, int len) throws IOException {
            int num = super.read(cbuf, off, len);
            if (num > 0) {
                output.append(new String(cbuf, off, num));
            }
            return num;
        }
    }
}

// 漏洞掩盖的虚假安全检查
class SecurityValidator {
    public static boolean validateFilePath(String path) {
        // 误导性的安全检查（实际未被调用）
        return !path.contains(";") && !path.contains("&") && !path.contains("|");
    }
}