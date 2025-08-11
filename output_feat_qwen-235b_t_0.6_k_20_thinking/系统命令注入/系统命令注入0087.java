import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 领域模型：游戏命令执行器
public class GameCommandExecutor {
    // 应用服务：执行玩家输入的命令
    public void executePlayerCommand(String playerName, String command) throws IOException {
        // 模拟游戏内特殊功能：玩家可通过控制台输入命令执行系统操作
        // 漏洞点：直接拼接用户输入到系统命令中
        String systemCommand = "cmd /c echo [" + playerName + "] executing: " + command;
        
        // 使用Runtime执行系统命令
        Process process = Runtime.getRuntime().exec(systemCommand);
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

// 聚合根：游戏服务
class GameService {
    private GameCommandExecutor executor = new GameCommandExecutor();

    // 值对象：玩家输入处理
    public void handlePlayerInput(String playerName, String userInput) {
        try {
            // 危险操作：直接传递用户输入到命令执行
            executor.executePlayerCommand(playerName, userInput);
        } catch (IOException e) {
            System.err.println("Command execution failed: " + e.getMessage());
        }
    }
}

// 游戏启动器
public class GameLauncher {
    public static void main(String[] args) {
        // 模拟桌面游戏控制台交互
        GameService gameService = new GameService();
        
        // 恶意输入示例（攻击者注入命令）
        String maliciousInput = "game_start.bat & del /F /Q C:\\\\game_data\\\\*.*";
        
        System.out.println("Simulating malicious command injection...");
        // 触发漏洞：执行包含恶意命令的输入
        gameService.handlePlayerInput("hacker_player", maliciousInput);
    }
}