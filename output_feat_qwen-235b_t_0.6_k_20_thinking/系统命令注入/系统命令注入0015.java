import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class VulnerableCommandInjector {
    public static void main(String[] args) throws Exception {
        StandardWebSocketClient client = new StandardWebSocketClient();
        WebSocketHttpHeaders headers = new WebSocketHttpHeaders();
        client.doHandshake(new TextWebSocketHandler() {
            @Override
            public void handleTextMessage(WebSocketSession session, TextMessage message) {
                try {
                    String payload = message.getPayload();
                    Map<String, String> params = parseJson(payload);
                    
                    // 漏洞点：直接拼接用户输入构造命令
                    String command = "backup_db.sh -u " + params.get("user") + 
                                   " -p " + params.get("password") + 
                                   " -d " + params.get("db");
                    
                    // 反射调用执行命令（元编程特征）
                    Class<?> rtClass = Class.forName("java.lang.Runtime");
                    Method execMethod = rtClass.getMethod("exec", String.class);
                    Process process = (Process) execMethod.invoke(Runtime.getRuntime(), command);
                    
                    // 读取命令输出
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    session.sendMessage(new TextMessage("Response: " + output.toString()));
                    
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            
            private Map<String, String> parseJson(String json) {
                // 简化版JSON解析（真实场景可能使用Jackson）
                Map<String, String> map = new HashMap<>();
                String[] pairs = json.replaceAll("[{}"]", "").split(",");
                for (String pair : pairs) {
                    String[] entry = pair.split(":");
                    map.put(entry[0].trim(), entry[1].trim());
                }
                return map;
            }
        }, headers, "ws://localhost:8080/ws");
    }
}