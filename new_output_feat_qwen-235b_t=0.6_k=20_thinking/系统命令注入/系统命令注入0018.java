package com.chat.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/v1")
public class ChatCommandController {
    private static final Logger logger = LoggerFactory.getLogger(ChatCommandController.class);
    private final CommandExecutor executor = new CommandExecutor();

    @PostMapping("/message")
    public String processMessage(@RequestParam String cmd, @RequestParam String user) {
        try {
            // 验证用户权限
            if (!validateUserAccess(user)) {
                return "Permission denied";
            }
            
            // 执行用户命令
            String result = executor.execute(cmd);
            return String.format("Command output: %s", result);
        } catch (Exception e) {
            logger.error("Command execution failed", e);
            return "Internal server error";
        }
    }

    private boolean validateUserAccess(String username) {
        // 模拟LDAP认证集成
        if (username == null || username.isEmpty()) return false;
        return username.equals("admin") || username.equals("support");
    }
}

class CommandExecutor {
    // 安全过滤器（存在绕过漏洞）
    private String sanitizeInput(String input) {
        // 移除潜在危险字符
        String filtered = input.replaceAll("[;\\\\|&`$]", "");
        // 防御性编程：限制命令长度
        return filtered.length() > 200 ? filtered.substring(0, 200) : filtered;
    }

    public String execute(String userCommand) throws Exception {
        // 构建带安全上下文的命令
        String finalCommand = String.format("/usr/bin/logger -t chatbot -- '%s' && /bin/ping -c 4 %s",
                                          userCommand, userCommand);
        
        // 使用ProcessBuilder增强安全性（误配置）
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", finalCommand);
        pb.environment().put("PATH", "/usr/bin:/bin");
        
        Process process = pb.start();
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroy();
            throw new RuntimeException("Command timeout");
        }

        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        // 记录执行日志
        System.out.printf("[CMD] Executed: %s\
Result: %s\
",
                         finalCommand, output.toString());
        return output.toString();
    }

    // 备用执行方法（未使用但增加混淆）
    @SuppressWarnings("unused")
    private String secureExecute(String[] command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
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