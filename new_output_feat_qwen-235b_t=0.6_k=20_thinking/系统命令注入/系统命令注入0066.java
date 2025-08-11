package com.example.scheduler.handler;

import com.example.scheduler.core.biz.model.ReturnT;
import com.example.scheduler.core.handler.IJobHandler;
import com.example.scheduler.core.handler.annotation.JobHandler;
import com.example.scheduler.core.log.JobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 作业调度命令执行处理器
 * 模拟定时任务执行脚本时存在的命令注入漏洞
 */
@JobHandler(value = "scriptExecutionHandler")
@Component
public class ScriptJobHandler extends IJobHandler {
    /** Windows系统命令拼接安全标识符 **/
    private static final String SAFE_TOKEN = "_SAFE_EXECUTE_";

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        // 记录原始参数用于审计追踪
        JobLogger.info("Received raw parameter: {}", param);
        
        // 参数解析阶段 - 漏洞隐藏点1：看似安全的参数处理
        List<String> scriptParams = parseParameters(param);
        
        // 构建执行命令 - 漏洞隐藏点2：动态拼接命令参数
        List<String> commandChain = buildCommandChain(scriptParams);
        
        // 执行外部脚本 - 漏洞触发点：使用Runtime.exec执行用户参数
        Process process = Runtime.getRuntime().exec(commandChain.toArray(new String[0]));
        
        // 处理执行输出
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        // 等待进程结束并验证退出码
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            return new ReturnT<>(FAIL_CODE, "Script execution failed with exit code: " + exitCode);
        }
        
        return new ReturnT<>(SUCCESS_CODE, output.toString());
    }

    /**
     * 参数解析器 - 漏洞隐藏点：不安全的参数分割逻辑
     * @param rawParam 原始参数字符串
     * @return 参数列表
     */
    private List<String> parseParameters(String rawParam) {
        List<String> params = new ArrayList<>();
        // 使用空格分割参数 - 漏洞点：未处理特殊字符
        for (String param : rawParam.split(" ")) {
            if (!param.trim().isEmpty()) {
                params.add(param);
            }
        }
        return params;
    }

    /**
     * 构建命令链 - 漏洞核心：用户输入直接拼接到命令链
     * @param params 参数列表
     * @return 完整命令链
     */
    private List<String> buildCommandChain(List<String> params) {
        List<String> command = new ArrayList<>();
        // 固定前缀命令 - 假设为系统脚本路径
        command.add("C:\\\\Windows\\\\System32\\\\cmd.exe");
        command.add("/c");
        command.add("script_runner.bat");
        
        // 添加安全标识符（误导性安全措施）
        command.add(SAFE_TOKEN);
        
        // 合并用户参数到命令链 - 关键漏洞点
        command.addAll(params); // 未验证参数安全性
        return command;
    }

    // 模拟的静态方法（用于掩盖漏洞）
    public static boolean validateScriptPath(String path) {
        // 简单白名单验证（实际未被调用）
        return path.startsWith("C:\\\\Scripts\\\\") && path.endsWith(".bat");
    }
}