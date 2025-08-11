import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

/**
 * 游戏存档管理器 - 模拟桌面游戏存档加载功能
 * 存在路径遍历漏洞的实现
 */
public class GameArchiveManager {
    private static final String BASE_DIR = "./game_saves/";
    
    /**
     * 保存游戏存档
     * @param archiveName 存档文件名
     * @param data 存档数据
     * @throws IOException
     */
    public void saveGameArchive(String archiveName, byte[] data) throws IOException {
        // 漏洞点：直接拼接用户输入
        File file = new File(BASE_DIR + archiveName + ".sav");
        
        // 创建父目录（如果不存在）
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        // 写入存档数据
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
    
    /**
     * 加载游戏存档
     * @param archiveName 存档文件名
     * @return 存档数据
     * @throws IOException
     */
    public byte[] loadGameArchive(String archiveName) throws IOException {
        // 漏洞点：直接拼接用户输入
        File file = new File(BASE_DIR + archiveName + ".sav");
        
        // 读取存档数据
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }
    
    public static void main(String[] args) {
        GameArchiveManager manager = new GameArchiveManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 桌面游戏存档系统 ===");
        System.out.print("请输入存档名称: ");
        String archiveName = scanner.nextLine();
        
        try {
            // 模拟保存操作
            System.out.println("正在保存存档...");
            manager.saveGameArchive(archiveName, "游戏进度数据".getBytes());
            
            // 模拟加载操作
            System.out.println("正在加载存档...");
            byte[] data = manager.loadGameArchive(archiveName);
            System.out.println("加载成功: " + new String(data));
            
        } catch (IOException e) {
            System.err.println("操作失败: " + e.getMessage());
        }
        
        scanner.close();
    }
}