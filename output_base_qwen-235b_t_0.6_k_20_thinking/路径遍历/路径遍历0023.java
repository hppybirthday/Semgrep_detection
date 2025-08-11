import java.io.*;
import java.util.Scanner;

class ResourceLoader {
    private String basePath;

    public ResourceLoader(String basePath) {
        this.basePath = basePath;
    }

    public void loadResource(String userInput) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        String fullPath = basePath + "\\\\" + userInput;
        File file = new File(fullPath);
        
        // 未进行路径规范化检查
        if (file.exists() && file.isFile()) {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } else {
            System.out.println("资源不存在");
        }
    }
}

class GameSettings {
    private String configPath;

    public GameSettings(String configPath) {
        this.configPath = configPath;
    }

    public void displayConfig() throws IOException {
        File file = new File(configPath);
        if (file.exists()) {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        }
    }
}

public class DesktopGame {
    public static void main(String[] args) {
        try {
            // 假设游戏资源存储在安装目录下的resources文件夹
            ResourceLoader loader = new ResourceLoader("C:\\\\game\\\\resources");
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("请输入要加载的资源名称（示例：textures\\\\player.skin）：");
            String userInput = scanner.nextLine();
            
            // 漏洞利用示例：输入 "..\\\\..\\\\..\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"
            // 将会读取系统文件
            loader.loadResource(userInput);
            
            // 游戏其他正常功能
            GameSettings settings = new GameSettings("C:\\\\game\\\\config\\\\settings.cfg");
            settings.displayConfig();
            
        } catch (Exception e) {
            System.out.println("错误：" + e.getMessage());
        }
    }
}