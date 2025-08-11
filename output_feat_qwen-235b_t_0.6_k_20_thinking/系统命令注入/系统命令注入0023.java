import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

public class GameLauncher {
    public static void main(String[] args) {
        GameBackup backupManager = new GameBackup();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 桌面游戏存档管理系统 ===");
        System.out.print("输入存档文件名进行备份: ");
        String filename = scanner.nextLine();
        
        try {
            backupManager.backupGame(filename);
        } catch (IOException e) {
            System.err.println("备份失败: " + e.getMessage());
        }
    }
}

class GameBackup {
    public void backupGame(String filename) throws IOException {
        // 模拟跨平台命令执行
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder processBuilder;
        
        if (os.contains("win")) {
            // Windows系统
            processBuilder = new ProcessBuilder("cmd.exe", "/c", "tar -czf C:\\\\backup\\" + filename + ".tar.gz C:\\\\game\\data");
        } else {
            // Unix-like系统
            processBuilder = new ProcessBuilder("/bin/sh", "-c", "tar -czf /backup/" + filename + ".tar.gz /game/data");
        }
        
        // 漏洞点：未对filename参数进行安全校验
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        // 读取命令执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        
        try {
            int exitCode = process.waitFor();
            System.out.println("备份完成，退出码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("备份进程被中断");
        }
    }
}