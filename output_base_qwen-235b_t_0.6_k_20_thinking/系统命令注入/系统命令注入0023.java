import java.io.*;
import java.util.Scanner;

class GameManager {
    public void executeCommand(String command) {
        try {
            // 模拟游戏调试模式执行系统命令
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[调试输出]: " + line);
            }
        } catch (Exception e) {
            System.err.println("命令执行失败: " + e.getMessage());
        }
    }
}

class PlayerProfile {
    private String playerName;
    
    public PlayerProfile(String name) {
        this.playerName = name;
    }
    
    public String getPlayerName() {
        return playerName;
    }
}

public class DesktopGame {
    private static GameManager gameManager = new GameManager();
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 桌面游戏调试系统 ===");
        System.out.println("输入玩家名称：");
        String playerName = scanner.nextLine();
        
        PlayerProfile profile = new PlayerProfile(playerName);
        System.out.println("欢迎, " + profile.getPlayerName() + "!");
        
        while (true) {
            System.out.print("输入游戏命令（exit退出）> ");
            String command = scanner.nextLine();
            
            if (command.equalsIgnoreCase("exit")) {
                break;
            }
            
            // 危险：直接执行用户输入的命令
            gameManager.executeCommand(command);
        }
        
        scanner.close();
        System.out.println("游戏结束");
    }
}