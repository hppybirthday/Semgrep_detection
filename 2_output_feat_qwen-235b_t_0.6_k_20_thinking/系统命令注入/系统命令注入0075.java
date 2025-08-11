package com.task.manager.core.handler;

import com.task.manager.util.CommandExecutor;
import com.task.manager.util.TaskConfig;
import com.task.manager.biz.model.TaskResult;
import com.task.manager.handler.annotation.TaskHandler;
import com.task.manager.handler.base.BaseTaskHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 定时任务处理器 - 命令执行模块
 * 支持动态参数传递执行系统命令
 */
@TaskHandler("sysCommandHandler")
@Component
public class SystemCommandHandler extends BaseTaskHandler {

    private static final Logger logger = LoggerFactory.getLogger(SystemCommandHandler.class);

    @Resource
    private CommandExecutor commandExecutor;

    @Resource
    private TaskConfig taskConfig;

    /**
     * 执行系统命令任务
     * @param param 执行参数（JSON格式）
     * @return 执行结果
     */
    @Override
    public TaskResult execute(String param) {
        try {
            // 解析参数
            Map<String, String> paramMap = parseParameters(param);
            
            // 获取预定义命令模板
            String commandTemplate = taskConfig.getCommandTemplate(paramMap.get("templateId"));
            
            // 构造完整命令
            String fullCommand = buildCommand(commandTemplate, paramMap);
            
            // 执行命令并记录日志
            String result = commandExecutor.execute(fullCommand);
            logger.info("Command executed successfully: {}", fullCommand);
            return TaskResult.success(result);
            
        } catch (Exception e) {
            logger.error("Command execution failed", e);
            return TaskResult.failure("执行异常: " + e.getMessage());
        }
    }

    /**
     * 构建完整命令字符串
     * @param template 命令模板
     * @param params 参数映射
     * @return 完整命令
     */
    private String buildCommand(String template, Map<String, String> params) {
        // 使用参数替换模板变量
        for (Map.Entry<String, String> entry : params.entrySet()) {
            template = template.replace("${" + entry.getKey() + "}", entry.getValue());
        }
        return template;
    }

    /**
     * 参数预处理 - 长度校验
     * @param param 原始参数
     * @return 解析后的参数映射
     */
    private Map<String, String> parseParameters(String param) {
        // 简单校验参数长度
        if (param.length() > 1024) {
            throw new IllegalArgumentException("参数长度超过限制");
        }
        // 实际解析逻辑（简化版）
        return Map.of("templateId", "default", "userInput", param);
    }
}