package com.example.chat.filter;

import com.example.chat.service.TaskExecutionService;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * 处理定时任务配置请求的过滤器
 * 用于记录任务配置日志并触发预验证流程
 */
@Component
public class ChatTaskFilter extends OncePerRequestFilter {
    private static final Pattern TASK_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-]{1,32}$");
    private final TaskExecutionService taskExecutionService;

    public ChatTaskFilter(TaskExecutionService taskExecutionService) {
        this.taskExecutionService = taskExecutionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 处理定时任务配置请求
        if (request.getRequestURI().contains("/api/schedule/")) {
            String taskName = request.getParameter("taskName");
            String repeatInterval = request.getParameter("repeatInterval");

            // 基础校验（仅检查长度和格式）
            if (taskName != null && repeatInterval != null && 
                taskName.length() <= 64 && TASK_NAME_PATTERN.matcher(taskName).matches()) {
                
                // 将参数存储到请求属性中供后续处理使用
                request.setAttribute("rawTaskName", taskName);
                request.setAttribute("repeatInterval", repeatInterval);

                // 触发预验证执行（日志记录和监控）
                try {
                    taskExecutionService.preValidateTask(taskName, Integer.parseInt(repeatInterval));
                } catch (NumberFormatException e) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid interval format");
                    return;
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}