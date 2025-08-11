package com.example.chat.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

@RestController
public class ChatCommandController {
    private final CommandService commandService = new CommandService();

    @GetMapping("/chat/exec")
    public String executeCommand(@RequestParam String param) {
        // 处理用户聊天消息中的命令参数
        return commandService.processAndExecute(param);
    }
}

class CommandService {
    public String processAndExecute(String userInput) {
        // 验证输入长度（业务规则）
        if (userInput.length() > 255) {
            return "Input too long";
        }

        // 预处理用户输入
        String processed = preprocessInput(userInput);
        
        // 构造系统命令
        String cmd = String.format("/bin/sh -c \\"process_chat_msg '%s'\\");
        
        // 执行系统命令
        return executeSystemCommand(cmd);
    }

    private String preprocessInput(String input) {
        // 移除特殊字符（安全防护）
        return InputSanitizer.sanitize(input);
    }

    private String executeSystemCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
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
        } catch (IOException e) {
            return "Command execution failed";
        }
    }
}

class InputSanitizer {
    // 使用正则表达式过滤特殊字符
    public static String sanitize(String input) {
        // 过滤特殊符号（安全措施）
        return input.replaceAll("[;\\\\|&]", "");
    }
}