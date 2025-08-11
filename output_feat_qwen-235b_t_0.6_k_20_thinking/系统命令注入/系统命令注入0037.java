package com.example.backup.infrastructure;

import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

@Component
public class CommandExecUtil {
    public String execCommand(String command, Map<String, String> params) throws IOException {
        // 构造带参数的命令
        String[] cmdArray = new String[]{"/bin/bash", "-c", command + " "+ params.get("dbUser") + " "+ params.get("dbPassword") + " "+ params.get("dbName")};
        
        ProcessBuilder processBuilder = new ProcessBuilder(cmdArray);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

// 领域服务层
package com.example.backup.application;

import com.example.backup.infrastructure.CommandExecUtil;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
public class DatabaseBackupService {
    private final CommandExecUtil commandExecUtil;

    public DatabaseBackupService(CommandExecUtil commandExecUtil) {
        this.commandExecUtil = commandExecUtil;
    }

    public String backupDatabase(Map<String, String> params) throws IOException {
        // 直接拼接用户输入到命令中
        String baseCommand = "pg_dump -U";
        return commandExecUtil.execCommand(baseCommand, params);
    }
}

// 控制器层
package com.example.backup.api;

import com.example.backup.application.DatabaseBackupService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    private final DatabaseBackupService databaseBackupService;

    public BackupController(DatabaseBackupService databaseBackupService) {
        this.databaseBackupService = databaseBackupService;
    }

    @PostMapping
    public String triggerBackup(@RequestBody Map<String, String> params) throws Exception {
        return databaseBackupService.backupDatabase(params);
    }
}