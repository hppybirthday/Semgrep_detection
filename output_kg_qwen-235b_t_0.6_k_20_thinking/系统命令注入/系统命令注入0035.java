package com.example.taskmanager.handler;

import com.example.taskmanager.job.IJobHandler;
import com.example.taskmanager.job.JobHandler;
import com.example.taskmanager.log.TaskLogger;
import com.example.taskmanager.util.DynamicCommandBuilder;

import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * 动态命令任务处理器
 * 使用反射和动态命令构建实现元编程风格
 * @author dev-ops
 */
@JobHandler(value="dynamicCommandHandler")
public class DynamicCommandHandler extends IJobHandler {
    
    // 模拟元编程中的动态方法映射
    private Map<String, Method> commandMethods = new HashMap<>();

    public DynamicCommandHandler() {
        try {
            // 初始化动态命令映射（模拟元编程特性）
            commandMethods.put("process", this.getClass().getMethod("executeCommand", String[].class));
            commandMethods.put("run", this.getClass().getMethod("executeCommand", String[].class));
        } catch (Exception e) {
            TaskLogger.error("初始化动态命令映射失败: {}", e.getMessage());
        }
    }

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        try {
            // 元编程核心：动态解析参数结构
            String[] params = parseDynamicParams(param);
            
            // 动态选择执行方法（反射调用）
            Method targetMethod = commandMethods.getOrDefault(params[0], this.getClass().getMethod("executeCommand", String[].class));
            
            // 执行动态命令
            Process process = (Process) targetMethod.invoke(this, new Object[]{params});
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(new BufferedInputStream(process.getInputStream()))
            );
            
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
                TaskLogger.info("执行输出: {}", line);
            }
            
            process.waitFor();
            return process.exitValue() == 0 ? SUCCESS : new ReturnT<>(FAIL.getCode(), "执行失败: " + result);
            
        } catch (Exception e) {
            TaskLogger.error("任务执行异常: {}", e.getMessage());
            return new ReturnT<>(FAIL.getCode(), "执行异常: " + e.getMessage());
        }
    }

    /**
     * 动态参数解析方法（存在安全缺陷）
     * @param param 原始参数
     * @return 解析后的参数数组
     */
    private String[] parseDynamicParams(String param) {
        // 使用空格分隔参数（未进行任何安全过滤）
        return param.split(" ");
    }

    /**
     * 动态命令执行方法
     * @param params 参数数组
     * @return 执行的进程对象
     * @throws Exception 执行异常
     */
    public Process executeCommand(String[] params) throws Exception {
        // 构建命令字符串（危险的元编程实现）
        StringBuilder commandBuilder = new StringBuilder();
        for (String param : params) {
            commandBuilder.append(param).append(" ");
        }
        
        // 存在漏洞的系统命令执行（关键漏洞点）
        TaskLogger.info("执行动态命令: {}", commandBuilder.toString());
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", commandBuilder.toString()});
    }
}