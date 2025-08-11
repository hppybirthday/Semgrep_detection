package com.cloudnative.demo.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;

@Service
@ServerEndpoint("/ws/cmd")
public class CommandExecutionService {
    
    private static final String CMD_TEMPLATE = "sh -c \\"%s\\"";
    private static final List<String> ALLOWED_COMMANDS = List.of("ls", "cat", "grep");
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @Autowired
    private Environment env;
    
    private static final CopyOnWriteArraySet<Session> sessions = new CopyOnWriteArraySet<>();
    
    @OnOpen
    public void onOpen(Session session) {
        sessions.add(session);
    }
    
    @OnMessage
    public void onMessage(String input, Session session) {
        try {
            String sanitized = sanitizeInput(input);
            if (sanitized == null) {
                session.getBasicRemote().sendText("Invalid command");
                return;
            }
            
            TaskConfig config = getTaskConfigFromDatabase(input);
            String finalCmd = buildCommand(config, sanitized);
            
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", finalCmd);
            pb.environment().put("PATH", env.getProperty("safe.path"));
            Process process = pb.start();
            
            String output = new BufferedReader(
                new InputStreamReader(process.getInputStream()))
                .lines().collect(Collectors.joining("\
"));
            
            session.getBasicRemote().sendText(output);
            
        } catch (Exception e) {
            logger.error("Command execution failed: {}", e.getMessage());
            try {
                session.getBasicRemote().sendText("Execution error");
            } catch (IOException ex) {
                // Ignore
            }
        }
    }
    
    private String sanitizeInput(String input) {
        if (input == null || input.isEmpty()) return null;
        
        String[] parts = input.split(" ", 2);
        if (!ALLOWED_COMMANDS.contains(parts[0])) {
            return null;
        }
        
        return input.replace("..", ""); // Simple path traversal filter
    }
    
    private TaskConfig getTaskConfigFromDatabase(String input) {
        List<Map<String, Object>> result = jdbcTemplate.queryForList(
            "SELECT * FROM task_configs WHERE command = '" + input + "' LIMIT 1"");
        
        if (result.isEmpty()) {
            return new TaskConfig("default", input);
        }
        
        Map<String, Object> row = result.get(0);
        return new TaskConfig((String)row.get("id"), (String)row.get("command"));
    }
    
    private String buildCommand(TaskConfig config, String sanitized) {
        String baseCmd = String.format(CMD_TEMPLATE, sanitized);
        if (config.getId().equals("critical")) {
            return baseCmd + " && echo \\"[ADMIN CMD]\\"";
        }
        return baseCmd;
    }
    
    static class TaskConfig {
        private final String id;
        private final String command;
        
        TaskConfig(String id, String command) {
            this.id = id;
            this.command = command;
        }
        
        public String getId() { return id; }
        public String getCommand() { return command; }
    }
}