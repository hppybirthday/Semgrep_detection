import java.io.*;
import java.nio.file.*;
import java.util.*;

// 领域模型：游戏存档
public class GameArchive {
    private final String name;
    private final String content;

    public GameArchive(String name, String content) {
        this.name = name;
        this.content = content;
    }

    public String getName() { return name; }
    public String getContent() { return content; }
}

// 领域服务：游戏加载器
class GameLoader {
    private static final String SAVE_DIR = "saves/";

    public GameArchive loadGame(String archiveName) throws IOException {
        // 漏洞点：直接拼接用户输入
        Path path = Paths.get(SAVE_DIR + archiveName);
        
        // 模拟读取存档文件
        if (!Files.exists(path)) {
            throw new FileNotFoundException("存档不存在: " + archiveName);
        }
        
        // 读取文件内容
        String content = new String(Files.readAllBytes(path));
        return new GameArchive(archiveName, content);
    }
}

// 应用服务：存档管理
class ArchiveManager {
    private final GameLoader gameLoader = new GameLoader();

    public void loadAndDisplayArchive(String userInput) {
        try {
            GameArchive archive = gameLoader.loadGame(userInput);
            System.out.println("加载成功: " + archive.getName());
            System.out.println("内容预览: " + archive.getContent().substring(0, Math.min(50, archive.getContent().length())));
        } catch (Exception e) {
            System.err.println("加载失败: " + e.getMessage());
        }
    }
}

// 基础设施：控制台界面
public class GameConsole {
    public static void main(String[] args) {
        ArchiveManager manager = new ArchiveManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 桌面游戏存档加载器 ===");
        System.out.println("请输入存档名称（示例：save1.dat）：");
        
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine();
            
            if (input.equalsIgnoreCase("exit")) {
                break;
            }
            
            manager.loadAndDisplayArchive(input);
        }
        
        scanner.close();
    }
}