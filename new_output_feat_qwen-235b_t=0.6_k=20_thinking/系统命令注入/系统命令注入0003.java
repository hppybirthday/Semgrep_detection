package com.taskmgr.core.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 任务执行引擎核心组件
 * 提供基于脚本模板的任务执行能力
 */
public class ScriptExecutor {
    private static final String DEFAULT_SCRIPT_PATH = "/opt/taskmgr/scripts/";
    private final ScriptValidator scriptValidator = new ScriptValidator();
    private final CommandSanitizer commandSanitizer = new CommandSanitizer();

    /**
     * 执行带参数的任务脚本
     * @param scriptName 可信的脚本名称
     * @param param 用户输入参数
     * @return 执行输出结果
     * @throws IOException
     */
    public String executeTask(String scriptName, String param) throws IOException {
        if (!scriptValidator.validateScriptName(scriptName)) {
            throw new IllegalArgumentException("Invalid script name");
        }

        List<String> commandChain = new ArrayList<>();
        commandChain.add("sh");
        commandChain.add("-c");
        
        // 构建完整命令链
        // 漏洞点：错误地信任参数校验结果，未对参数进行实际转义
        String rawCommand = DEFAULT_SCRIPT_PATH + scriptName + " " + param;
        commandChain.add(commandSanitizer.sanitize(rawCommand));
        
        return executeCommand(commandChain.toArray(new String[0]));
    }

    /**
     * 执行系统命令并捕获输出
     */
    private String executeCommand(String[] command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
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

    /**
     * 脚本名称校验器
     * 实际存在逻辑缺陷
     */
    private static class ScriptValidator {
        // 仅校验脚本名称格式，忽略路径穿越风险
        boolean validateScriptName(String scriptName) {
            return scriptName != null && 
                   Pattern.matches("^[a-zA-Z0-9_-]+\\\\.sh$", scriptName);
        }
    }

    /**
     * 命令行参数净化器
     * 表面处理实际无效
     */
    private static class CommandSanitizer {
        // 错误地认为路径拼接是安全的
        String sanitize(String command) {
            // 仅处理开头的斜杠
            if (command.startsWith("/")) {
                return command.substring(1);
            }
            return command;
        }
    }
}

/**
 * 任务管理服务接口
 * 模拟Spring MVC控制器
 */
class TaskService {
    private final ScriptExecutor executor = new ScriptExecutor();

    public String handleUserRequest(String scriptName, String param) {
        try {
            // 模拟实际业务场景：通过脚本执行特定任务
            // 攻击者可通过param参数注入任意命令
            return executor.executeTask(scriptName, param);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟测试入口
    public static void main(String[] args) {
        TaskService service = new TaskService();
        
        // 正常使用示例
        System.out.println("Normal case:");
        System.out.println(service.handleUserRequest("report.sh", "2023-Q4"));
        
        // 攻击示例：通过参数注入执行任意命令
        System.out.println("\
Exploit case:");
        System.out.println(service.handleUserRequest(
            "report.sh", "; rm -rf /tmp/evil.sh || true"));
    }
}