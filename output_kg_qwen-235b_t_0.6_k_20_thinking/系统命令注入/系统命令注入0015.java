package com.example.demo;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.lang.ArrayUtils;
import java.io.*;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.logging.Logger;

@RestController
@RequestMapping("/vulnerable")
public class VulnerableCommandService {
    private static final Logger logger = Logger.getLogger(VulnerableCommandService.class.getName());

    @GetMapping
    public String execute(@RequestParam String command, @RequestParam String[] args) {
        try {
            // 模拟元编程风格：通过反射动态获取执行方法
            Class<?> clazz = Class.forName("com.example.demo.CommandExecutor");
            Method method = clazz.getMethod("exec", String.class, String[].class);
            
            // 危险：直接拼接用户输入到命令参数
            String[] fullCommand = (String[]) ArrayUtils.addAll(new String[]{command}, args);
            Object result = method.invoke(null, "execCommand", fullCommand);
            return result.toString();
        } catch (Exception e) {
            logger.severe("Execution error: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    // 动态生成的执行类（模拟元编程）
    public static class CommandExecutor {
        public static String execCommand(String dummy, String[] command) throws IOException {
            Process process = Runtime.getRuntime().exec(command);
            
            // 记录执行日志
            logger.info("Executing command: " + Arrays.toString(command));
            
            // 读取输出流
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\\\
");
            }
            
            // 错误流处理（简化版）
            new Thread(() -> {
                try (BufferedReader errReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                    String errLine;
                    while ((errLine = errReader.readLine()) != null) {
                        logger.warning("Error output: " + errLine);
                    }
                } catch (IOException e) {
                    logger.severe("Error stream read error: " + e.getMessage());
                }
            }).start();
            
            process.destroy();
            return output.toString();
        }
    }

    // 伪装的过滤函数（未实际启用）
    private String sanitizeInput(String input) {
        // 开发者注释：TODO 需要实现输入过滤
        return input.replaceAll("([&|;`\\\\\\\\])", "\\\\\\\\\\\\\\"$1\\\\\\\\\\\\""); // 错误实现
    }
}