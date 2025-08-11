package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class CommandController {
    @GetMapping("/")
    public String executeCommand(@RequestParam(name = "cmd_", required = false) String cmd) {
        if (cmd == null || cmd.isEmpty()) {
            return "Missing command parameter";
        }
        
        // 模拟防御式编程的错误实现
        if (!isValidCommand(cmd)) {
            return "Invalid command format";
        }
        
        try {
            String fullCommand = String.format("sh -c \\"echo 'Input: %s'; %s\\"", cmd, cmd);
            String result = CommandExecUtil.execCommand(fullCommand);
            return String.format("<pre>Command output:\
%s</pre>", result);
        } catch (Exception e) {
            return "Error executing command";
        }
    }

    // 错误的验证逻辑
    private boolean isValidCommand(String cmd) {
        // 仅检查常见分隔符但忽略其他可能性
        if (cmd.contains(";") || cmd.contains("&&") || cmd.contains("||")) {
            return false;
        }
        // 允许特殊字符但限制长度
        return cmd.length() < 50;
    }

    static class CommandExecUtil {
        public static String execCommand(String command) throws IOException {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("[ERROR] ").append(line).append("\
");
            }
            return output.toString();
        }
    }
}