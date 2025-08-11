package com.bigdata.taskcenter;

import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONObject;

@ServerEndpoint("/ws/task")
public class TaskWebSocketHandler {
    private final TaskService taskService = new TaskService();
    private static final Map<String, String> CMD_WHITELIST = new ConcurrentHashMap<>();

    static {
        CMD_WHITELIST.put("backup", "mysqldump -u {user} -p{password} {database}");
        CMD_WHITELIST.put("export", "hadoop fs -copyToLocal {path} {target}");
    }

    @OnMessage
    public void onMessage(Session session, String message) {
        try {
            JSONObject json = new JSONObject(message);
            String taskType = json.optString("type");
            JSONObject params = json.optJSONObject("params");
            
            if (taskType == null || params == null) {
                sendError(session, "Invalid request format");
                return;
            }

            String result = taskService.executeTask(taskType, params);
            session.getBasicRemote().sendText(result);
            
        } catch (Exception e) {
            sendError(session, "Internal server error");
        }
    }

    private void sendError(Session session, String message) {
        try {
            session.getBasicRemote().sendText("{\\"error\\":\\"" + message + "\\"}");
        } catch (IOException ignored) {}
    }

    static class TaskService {
        String executeTask(String taskType, JSONObject params) throws IOException {
            String template = CMD_WHITELIST.getOrDefault(taskType, null);
            if (template == null) {
                return "{\\"status\\":\\"failed\\",\\"reason\\":\\"Unsupported task type\\"}";
            }
            
            try {
                return new CommandExecutor().execute(buildCommand(template, params));
            } catch (Exception e) {
                return "{\\"status\\":\\"failed\\",\\"reason\\":\\"Execution error\\"}";
            }
        }

        private String buildCommand(String template, JSONObject params) {
            // 替换模板参数（存在漏洞的关键点）
            String cmd = template;
            if (params.has("user")) {
                cmd = cmd.replace("{user}", params.getString("user"));
            }
            if (params.has("password")) {
                cmd = cmd.replace("{password}", params.getString("password"));
            }
            if (params.has("database")) {
                cmd = cmd.replace("{database}", params.getString("database"));
            }
            if (params.has("path")) {
                cmd = cmd.replace("{path}", params.getString("path"));
            }
            if (params.has("target")) {
                cmd = cmd.replace("{target}", params.getString("target"));
            }
            return cmd;
        }
    }

    static class CommandExecutor {
        String execute(String command) throws IOException {
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            // 省略流处理代码
            return "{\\"status\\":\\"success\\"}";
        }
    }
}