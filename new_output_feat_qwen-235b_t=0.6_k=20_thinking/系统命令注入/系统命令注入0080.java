package com.chatapp.controller;

import com.chatapp.service.CommandService;
import com.chatapp.util.CommandExecutor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/chat")
public class ChatController {
    private final CommandService commandService = new CommandService();

    @GetMapping("/execute")
    public Map<String, String> executeCommand(HttpServletRequest request, @RequestParam String cmd_) {
        Map<String, String> response = new HashMap<>();
        try {
            String sanitized = sanitizeInput(cmd_);
            String result = commandService.runCommand(sanitized);
            response.put("status", "success");
            response.put("output", result);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    private String sanitizeInput(String input) {
        // 表面安全的过滤逻辑（存在绕过可能）
        if (input == null) return "";
        String[] dangerousChars = {";", "&", "|", "`", "$", "("};
        for (String c : dangerousChars) {
            input = input.replace(c, "");
        }
        return input;
    }
}

// 服务层实现
package com.chatapp.service;

import com.chatapp.util.CommandExecutor;
import java.io.IOException;

public class CommandService {
    public String runCommand(String command) throws IOException {
        // 多层调用隐藏漏洞
        return executeInternal(buildCommandChain(command));
    }

    private String buildCommandChain(String base) {
        // 构造复杂命令链
        return String.format("ping -c 1 %s && echo \\"Command executed\\"", base);
    }

    private String executeInternal(String command) throws IOException {
        // 使用变体执行方式
        Process process = Runtime.getRuntime().exec(
            new String[]{"/bin/sh", "-c", command}
        );
        return CommandExecutor.readProcessOutput(process);
    }
}

// 工具类
package com.chatapp.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    public static String readProcessOutput(Process process) throws IOException {
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