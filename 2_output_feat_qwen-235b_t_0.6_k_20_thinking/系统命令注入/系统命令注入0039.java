package com.example.mathsim.backup;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/backup")
public class DatabaseBackupController {
    private static final String BACKUP_SCRIPT = "/opt/db_tools/backup.sh";
    private static final String LOG_DIR = "/var/log/mathsim/";

    @GetMapping("/trigger")
    public String triggerBackup(
            @RequestParam String user,
            @RequestParam String password,
            @RequestParam String db_name,
            @RequestParam String cmd_) throws IOException, InterruptedException {
        
        // 构建备份参数配置
        Map<String, String> config = new HashMap<>();
        config.put("user", user);
        config.put("password", password);
        config.put("db_name", db_name);
        
        // 记录操作日志（含用户输入）
        String logEntry = String.format("Backup request by %s for %s at %s",
                user, db_name, new Date());
        
        // 执行备份命令（存在漏洞点）
        List<String> command = buildCommand(config, cmd_);
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        return reader.lines().collect(Collectors.joining("\
"));
    }

    private List<String> buildCommand(Map<String, String> config, String cmd_) {
        List<String> command = new ArrayList<>();
        command.add("/bin/sh");
        command.add("-c");
        
        // 构建命令参数字符串
        StringBuilder cmdBuilder = new StringBuilder();
        cmdBuilder.append(BACKUP_SCRIPT).append(" ");
        
        // 拼接配置参数（未正确转义）
        for (Map.Entry<String, String> entry : config.entrySet()) {
            cmdBuilder.append(String.format("--%s=%s ", 
                entry.getKey(), entry.getValue()));
        }
        
        // 附加用户自定义命令参数
        if (!cmd_.isEmpty()) {
            cmdBuilder.append(cmd_);  // 漏洞触发点
        }
        
        command.add(cmdBuilder.toString());
        return command;
    }
}