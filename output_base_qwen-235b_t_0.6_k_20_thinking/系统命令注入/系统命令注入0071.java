import java.io.*;
import java.util.Scanner;

public class GameLauncher {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("===== 桌面游戏启动器 =====");
        System.out.println("1. 新游戏\
2. 加载存档\
3. 加载自定义地图");
        System.out.print("请选择操作: ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除换行符
        
        switch(choice) {
            case 1:
                startNewGame();
                break;
            case 2:
                loadSaveGame();
                break;
            case 3:
                System.out.print("请输入地图文件名: ");
                String mapFile = scanner.nextLine();
                loadCustomMap(mapFile);
                break;
            default:
                System.out.println("无效选择");
        }
    }
    
    private static void startNewGame() {
        System.out.println("正在初始化新游戏...");
        // 模拟游戏初始化
        executeCommand("echo 初始化游戏配置");
    }
    
    private static void loadSaveGame() {
        System.out.println("正在加载存档...");
        // 模拟存档加载
        executeCommand("echo 加载存档数据");
    }
    
    private static void loadCustomMap(String mapFile) {
        System.out.println("正在验证地图文件...");
        // 漏洞点：直接拼接用户输入到系统命令
        String command = "unzip -d ./maps/ " + mapFile;
        System.out.println("执行命令: " + command);
        executeCommand(command);
    }
    
    private static void executeCommand(String command) {
        try {
            // 漏洞：使用不安全的命令执行方式
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            int exitCode = process.waitFor();
            System.out.println("命令执行完成 (退出码 " + exitCode + ")");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}