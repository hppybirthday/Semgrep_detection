package com.crm.app.database;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 数据库备份WebSocket处理器
 * 通过WebSocket接收JSON格式的备份指令并执行系统命令
 */
@Component
public class DatabaseBackupHandler extends TextWebSocketHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CommandExecUtil commandExecUtil = new CommandExecUtil();

    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) {
        try {
            JsonNode payload = objectMapper.readTree(message.getPayload());
            if (payload.has("action") && "backup_db".equals(payload.get("action").asText())) {
                String dbType = sanitizeDbType(payload.get("db_type").asText());
                String backupDir = payload.get("backup_dir").asText();
                String result = executeBackupCommand(dbType, backupDir);
                session.sendMessage(new TextMessage("{\\"status\\":\\"success\\",\\"output\\":\\"" + result + "\\"}"));
            }
        } catch (Exception e) {
            // 记录异常但不暴露详细信息
            session.sendMessage(new TextMessage("{\\"status\\":\\"error\\",\\"message\\":\\"Internal error\\"}"));
        }
    }

    private String sanitizeDbType(String dbType) {
        // 看似安全的过滤逻辑（存在绕过可能）
        return dbType.replaceAll("[^a-zA-Z0-9]", "");
    }

    private String executeBackupCommand(String dbType, String backupDir) throws IOException {
        // 构造复杂命令执行链
        String baseCommand = String.format("mysqldump -u root -p");
        String fullCommand = baseCommand + " " + dbType + " > " + backupDir + "/backup.sql";
        return commandExecUtil.execCommand(fullCommand);
    }
}

class CommandExecUtil {
    String execCommand(String command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}