import java.io.*;
import java.util.*;

/**
 * 桌面游戏服务器启动器（存在系统命令注入漏洞）
 */
public class GameLauncher {
    private static final GameLogger logger = new GameLogger();

    public static void main(String[] args) {
        try {
            System.out.print("请输入游戏服务器名称: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String serverName = reader.readLine();
            
            // 构造带漏洞的服务器启动命令
            String result = GameCommandExecutor.execCommand(serverName);
            System.out.println("服务器启动结果: " + result);
        } catch (Exception e) {
            logger.error("启动服务器失败: " + e.getMessage());
        }
    }
}

class GameCommandExecutor {
    /**
     * 执行带漏洞的命令执行逻辑（错误示范）
     */
    public static String execCommand(String serverName) throws IOException {
        List<String> command = new ArrayList<>();
        
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            command.add("cmd.exe");
            command.add("/c");
            command.add("start-server.bat");
        } else {
            command.add("sh");
            command.add("-c");
            command.add("./start-server.sh");
        }
        
        // 危险操作：直接拼接用户输入到命令参数中
        command.add(serverName);

        ProcessBuilder builder = new ProcessBuilder(command);
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

class GameLogger {
    void error(String message) {
        System.err.println("[ERROR] " + message);
    }
}