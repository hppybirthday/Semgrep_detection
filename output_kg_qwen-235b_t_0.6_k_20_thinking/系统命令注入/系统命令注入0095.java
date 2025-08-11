package com.example.cloudservice;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class ConfigProcessor {
    
    private static final String CONFIG_SCRIPT = "./scripts/process_config.sh";
    
    @GetMapping("/render")
    public String renderConfig(@RequestParam String template, @RequestParam String params) {
        try {
            // 使用元编程动态构建执行逻辑
            Class<?> cmdUtil = Class.forName("com.example.cloudservice.CommandExecutor");
            Method execMethod = cmdUtil.getMethod("execute", String.class, Map.class);
            
            // 危险：直接将原始参数传递给动态执行方法
            return (String) execMethod.invoke(null, template, parseParams(params));
            
        } catch (Exception e) {
            return "Error processing config: " + e.getMessage();
        }
    }
    
    private Map<String, String> parseParams(String paramsStr) {
        // 简单的KV解析（存在注入风险）
        return Arrays.stream(paramsStr.split("&"))
            .map(pair -> pair.split("=", 2))
            .collect(Collectors.toMap(
                p -> p[0], 
                p -> p.length > 1 ? p[1] : ""
            ));
    }
    
    // 动态命令执行类（模拟元编程）
    public static class CommandExecutor {
        
        public static String execute(String template, Map<String, String> params) {
            try {
                // 构建命令参数（危险模式）
                List<String> cmd = new ArrayList<>();
                cmd.add("/bin/bash");
                cmd.add("-c");
                
                // 存在漏洞的命令拼接
                StringBuilder command = new StringBuilder();
                command.append(CONFIG_SCRIPT).append(" ")
                       .append(template).append(" ")
                       .append(params.toString()); // 直接拼接参数
                
                cmd.add(command.toString());
                
                ProcessBuilder pb = new ProcessBuilder(cmd);
                Process process = pb.start();
                
                // 收集输出结果
                AtomicReference<String> output = new AtomicReference<>("");
                new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(
                         new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                        output.set(reader.lines().collect(Collectors.joining("\
")));
                    } catch (Exception e) {
                        output.set("Stream error: " + e.getMessage());
                    }
                }).start();
                
                process.waitFor();
                return output.get();
                
            } catch (Exception e) {
                return "Execution failed: " + e.getMessage();
            }
        }
    }
    
    // 模拟的配置处理脚本（实际存在）
    static {
        try {
            File script = new File(CONFIG_SCRIPT);
            if (!script.exists()) {
                script.getParentFile().mkdirs();
                script.createNewFile();
                // 实际写入内容应为配置处理逻辑
                try (FileWriter writer = new FileWriter(script)) {
                    writer.write("#!/bin/bash\
echo \\"Processing config: $1\\"\
");
                }
            }
            new File("./scripts").mkdirs();
        } catch (Exception ignored) {}
    }
}