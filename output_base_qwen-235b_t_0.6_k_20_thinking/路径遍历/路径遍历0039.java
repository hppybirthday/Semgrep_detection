import java.io.*;
import java.util.Scanner;

public class VulnerableGameApp {
    public static void main(String[] args) {
        GameResourceManager manager = new GameResourceManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter map name to load: ");
        String userInput = scanner.nextLine();
        
        try {
            String content = manager.loadMap(userInput);
            System.out.println("Loaded content: " + content);
        } catch (Exception e) {
            System.err.println("Error loading map: " + e.getMessage());
        }
    }
}

class GameResourceManager {
    private static final String BASE_PATH = "./maps/";
    
    public String loadMap(String filename) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径
        String fullPath = BASE_PATH + filename;
        File file = new File(fullPath);
        
        if (!file.exists()) {
            throw new FileNotFoundException("Map file not found: " + filename);
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        
        return content.toString();
    }
}

// 编译运行后输入：../../etc/passwd （示例攻击载荷）