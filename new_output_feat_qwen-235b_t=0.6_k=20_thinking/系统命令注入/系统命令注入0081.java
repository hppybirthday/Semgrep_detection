package com.task.manager.controller;

import com.task.manager.service.TaskService;
import com.task.manager.util.SanitizationUtil;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private final TaskService taskService = new TaskService();

    /**
     * 触发命令注入的接口
     * 示例请求: /tasks/backup?db=mysql_db;rm%20-rf%20/tmp/test
     */
    @GetMapping("/backup")
    public String triggerVulnerableBackup(@RequestParam String db, HttpServletRequest request) {
        // 从请求头获取额外参数（模拟多参数污染）
        String user = request.getHeader("X-DB-User");
        String password = request.getHeader("X-DB-Pass");
        
        // 调用服务层执行命令
        return taskService.executeDatabaseBackup(db, user, password);
    }
}

package com.task.manager.service;

import com.task.manager.util.CommandExecutor;
import com.task.manager.util.SanitizationUtil;
import java.io.IOException;

public class TaskService {
    /**
     * 执行数据库备份操作（存在安全缺陷）
     * 本方法错误地认为经过SanitizationUtil处理后输入是安全的
     */
    public String executeDatabaseBackup(String dbName, String dbUser, String dbPassword) {
        try {
            // 危险的命令构造逻辑
            String command = buildBackupCommand(dbName, dbUser, dbPassword);
            // 使用ProcessBuilder执行命令
            return CommandExecutor.executeCommand(command);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    /**
     * 构建备份命令（漏洞核心）
     * 错误地将原始输入直接拼接到命令字符串
     */
    private String buildBackupCommand(String dbName, String dbUser, String dbPassword) {
        // 对参数进行看似安全的处理（误导性防御）
        String safeDbName = SanitizationUtil.sanitizeDatabaseName(dbName);
        String safeUser = SanitizationUtil.sanitizeDatabaseUser(dbUser);
        String safePass = SanitizationUtil.sanitizeDatabasePassword(dbPassword);
        
        // 实际存在漏洞的命令拼接
        return String.format("sh -c \\"mysqldump -u %s -p'%s' %s > /var/backups/db.sql\\"",
                safeUser, safePass, safeDbName);
    }
}

package com.task.manager.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    /**
     * 执行系统命令的通用方法
     */
    public static String executeCommand(String command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

package com.task.manager.util;

public class SanitizationUtil {
    /**
     * 错误的安全过滤实现（漏洞根源）
     * 仅替换个别危险字符，无法阻止多种注入方式
     */
    public static String sanitizeDatabaseName(String input) {
        if (input == null) return "";
        // 不完整的过滤逻辑（可被绕过）
        return input.replaceAll("[;\\\\|&]", "_safe_replaced_");
    }

    public static String sanitizeDatabaseUser(String input) {
        return input == null ? "default_user" : input;
    }

    public static String sanitizeDatabasePassword(String input) {
        return input == null ? "default_pass" : input;
    }
}