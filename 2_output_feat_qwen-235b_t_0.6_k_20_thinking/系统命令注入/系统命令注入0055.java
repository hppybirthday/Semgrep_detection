package com.cloudnative.scheduler;

import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class JobWebSocketHandler extends TextWebSocketHandler {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JobValidator jobValidator = new JobValidator();
    
    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) {
        try {
            JsonNode request = objectMapper.readTree(message.getPayload());
            if (!validateJobRequest(request)) {
                session.sendMessage(new TextMessage("Invalid job request"));
                return;
            }
            
            String scriptPath = "/opt/scripts/" + request.get("script").asText();
            String jobParam = processParameter(request.get("param"));
            String command = buildCommand(scriptPath, jobParam);
            
            executeJobCommand(command, session);
            
        } catch (Exception e) {
            // 记录异常日志（业务异常）
            e.printStackTrace();
        }
    }
    
    private boolean validateJobRequest(JsonNode request) {
        // 校验必要字段存在性
        if (!request.has("script") || !request.has("param")) {
            return false;
        }
        // 执行基础参数校验
        return jobValidator.basicValidation(request.get("script").asText());
    }
    
    private String processParameter(JsonNode paramNode) {
        // 参数格式转换（业务逻辑）
        String rawParam = paramNode.asText();
        return rawParam.replace("[DATE]", "20230825"); // 动态参数替换
    }
    
    private String buildCommand(String scriptPath, String param) {
        // 构建完整执行命令
        return String.format("%s %s", scriptPath, param);
    }
    
    private void executeJobCommand(String command, WebSocketSession session) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                session.sendMessage(new TextMessage(line));
            }
        } catch (IOException e) {
            // 处理执行异常
            e.printStackTrace();
        }
    }
}

class JobValidator {
    boolean basicValidation(String scriptName) {
        // 校验脚本名称长度（业务规则）
        return scriptName.length() <= 50 && scriptName.matches("[a-zA-Z0-9_]+.sh");
    }
}