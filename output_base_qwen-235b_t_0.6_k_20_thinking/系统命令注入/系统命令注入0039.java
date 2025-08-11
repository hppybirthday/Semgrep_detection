import java.util.Scanner;

interface CommandExecutor {
    void execute(String command);
}

class GameEngine {
    private CommandExecutor executor;

    public GameEngine(CommandExecutor executor) {
        this.executor = executor;
    }

    public void processDebugCommand(String input) {
        // 模拟游戏调试控制台功能
        if (input.startsWith("load_map")) {
            String mapName = input.replace("load_map", "").trim();
            executor.execute("game_assets/loader.exe -map " + mapName);
        } else if (input.startsWith("play_sound")) {
            String soundFile = input.replace("play_sound", "").trim();
            executor.execute("sndsys/play.exe -file " + soundFile);
        }
    }
}

class VulnerableExecutor implements CommandExecutor {
    @Override
    public void execute(String command) {
        try {
            // 存在漏洞的系统命令执行方式
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
            Process process = pb.start();
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public class DesktopGameLauncher {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        // 创建游戏引擎实例
        GameEngine engine = new GameEngine(new VulnerableExecutor());
        
        System.out.println("== 桌面游戏调试控制台 ==");
        System.out.println("输入命令（例：load_map scene1 或 play_sound music.wav）");
        
        while (true) {
            System.out.print(">> ");
            String input = scanner.nextLine();
            
            if (input.equalsIgnoreCase("exit")) {
                break;
            }
            
            engine.processDebugCommand(input);
        }
        
        scanner.close();
    }
}