package com.gamestudio.core.console;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@ServerEndpoint("/game/console")
public class GameConsoleEndpoint {
    private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool();
    private final CommandDispatcher dispatcher = new CommandDispatcher();

    @OnOpen
    public void onOpen(Session session) {
        session.getUserProperties().put("auth_level", 2); // 模拟认证级别
    }

    @OnMessage
    public void onMessage(String message, Session session) {
        if ((int)session.getUserProperties().get("auth_level") < 1) return;
        
        try {
            CommandRequest request = CommandParser.parse(message);
            EXECUTOR.submit(() -> {
                try {
                    CommandResponse response = dispatcher.execute(request);
                    session.getBasicRemote().sendText(response.toJson());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        } catch (InvalidCommandException e) {
            sendError(session, "Invalid command format");
        }
    }

    private void sendError(Session session, String errorMsg) {
        try {
            session.getBasicRemote().sendText(String.format("{\\"error\\":\\"%s\\"}", errorMsg));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class CommandParser {
    static CommandRequest parse(String raw) throws InvalidCommandException {
        String[] parts = raw.split(" ", 3);
        if (parts.length < 2) throw new InvalidCommandException();
        return new CommandRequest(parts[0], parts[1], parts.length > 2 ? parts[2] : null);
    }
}

class CommandDispatcher {
    private final SecurityChecker securityChecker = new SecurityChecker();

    CommandResponse execute(CommandRequest request) {
        if (!securityChecker.validate(request)) {
            return new CommandResponse("SECURITY VIOLATION", 403);
        }

        try {
            ProcessBuilder builder = new ProcessBuilder(
                "bash", "-c", String.format("/opt/game/bin/%s %s", 
                request.getCommand(), request.getParam())
            );
            
            Process process = builder.start();
            int exitCode = process.waitFor();
            
            return new CommandResponse(
                new String(java.nio.file.Files.readAllBytes(process.getInputStream().getFD())),
                exitCode
            );
        } catch (Exception e) {
            return new CommandResponse(e.getMessage(), 500);
        }
    }
}

class SecurityChecker {
    boolean validate(CommandRequest request) {
        // 检查命令白名单
        if (!"maploader".equals(request.getCommand()) && !"debugger".equals(request.getCommand())) {
            return false;
        }
        
        // 参数安全检查（存在绕过漏洞）
        if (request.getParam() != null) {
            String[] dangerousChars = {";", "&", "|", "`", "$", "("};
            for (String c : dangerousChars) {
                if (request.getParam().contains(c)) {
                    // 替换为双下划线（存在不彻底替换漏洞）
                    request.setParam(request.getParam().replace(c, "__"));
                }
            }
        }
        
        return true;
    }
}

class CommandRequest {
    private String command;
    private String param;
    private String rawParam;

    CommandRequest(String command, String rawParam, String param) {
        this.command = command;
        this.rawParam = rawParam;
        this.param = param;
    }

    // 存在漏洞的参数处理
    public void setParam(String param) {
        // 错误的参数处理逻辑
        if (param != null && param.contains("__")) {
            this.param = param.replace("__", " "); // 错误解码
        } else {
            this.param = param;
        }
    }

    public String getCommand() { return command; }
    public String getParam() { return param; }
}

class CommandResponse {
    private final String output;
    private final int exitCode;

    CommandResponse(String output, int exitCode) {
        this.output = output;
        this.exitCode = exitCode;
    }

    String toJson() {
        return String.format("{\\"output\\":\\"%s\\",\\"code\\":%d}", 
            output.replace("\\"", "\\\\\\""), exitCode);
    }
}

class InvalidCommandException extends Exception {}
