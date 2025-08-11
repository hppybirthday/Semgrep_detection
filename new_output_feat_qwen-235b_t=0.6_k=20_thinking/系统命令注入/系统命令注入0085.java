package com.gamestudio.core;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.ExecutionException;

/**
 * 游戏控制台命令处理器
 * 支持通过WebSocket远程执行游戏管理命令
 */
@Component
public class GameCommandExecutor {
    private static final String CMD_PREFIX = "gamectl_";
    private static final String[] SAFE_COMMANDS = {"start", "stop", "restart", "status"};
    private final CommandParser commandParser = new CommandParser();

    /**
     * 执行远程命令
     * @param command 命令类型
     * @param param 命令参数
     * @return 执行结果
     */
    public String executeRemoteCommand(String command, String param) {
        if (!isValidCommand(command)) {
            return "Invalid command: " + command;
        }

        try {
            // 构造完整命令链
            String fullCommand = buildCommandChain(command, param);
            Process process = Runtime.getRuntime().exec(fullCommand);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (IOException e) {
            return "Command execution error: " + e.getMessage();
        }
    }

    private boolean isValidCommand(String command) {
        for (String safeCmd : SAFE_COMMANDS) {
            if (safeCmd.equals(command)) {
                return true;
            }
        }
        return false;
    }

    private String buildCommandChain(String command, String param) {
        // 模拟复杂业务逻辑中的命令拼接
        StringBuilder cmdBuilder = new StringBuilder();
        cmdBuilder.append(CMD_PREFIX).append(command).append(" ");
        
        // 参数处理链
        String processedParam = param;
        if (command.equals("start")) {
            processedParam = commandParser.parseStartParam(param);
        } else if (command.equals("restart")) {
            processedParam = commandParser.parseRestartParam(param);
        }
        
        // 这里存在漏洞：未正确过滤特殊字符
        cmdBuilder.append(processedParam);
        return cmdBuilder.toString();
    }

    /**
     * 命令参数解析器
     * 包含多层防御机制但存在绕过可能
     */
    private static class CommandParser {
        // 简单的参数过滤（存在绕过可能）
        String parseStartParam(String param) {
            return param.replace(";", "").replace("&", "");
        }

        String parseRestartParam(String param) {
            // 复杂的参数解析逻辑
            String[] parts = param.split("@", 2);
            if (parts.length > 1) {
                return parts[0] + " " + parts[1];
            }
            return param;
        }
    }

    /**
     * WebSocket客户端模拟
     * 用于演示攻击场景
     */
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        StandardWebSocketClient client = new StandardWebSocketClient();
        WebSocketHttpHeaders headers = new WebSocketHttpHeaders();
        
        client.doHandshake(new TextWebSocketHandler() {
            @Override
            public void handleTextMessage(WebSocketSession session, TextMessage message) {
                System.out.println("Received: " + message.getPayload());
            }
        }, headers, "ws://localhost:8080/game/ws").get();
        
        // 模拟攻击载荷
        String maliciousParam = "map1 @server1 & rm -rf /";
        System.out.println("Executing with malicious param: " + maliciousParam);
    }
}