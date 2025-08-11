import java.io.*;
import java.util.*;

public class ChatApplication {
    public static void main(String[] args) {
        System.out.println("[INFO] 启动聊天服务器 v2.1");
        DatabaseTool databaseTool = new DatabaseTool();
        
        // 模拟用户上传文件
        String[] testFilenames = {
            "profile.jpg",
            "photo.png; rm -rf /tmp/*; echo MALICIOUS_EXECUTION > /tmp/pwned.txt",
            "document.pdf"
        };
        
        for (String filename : testFilenames) {
            System.out.println("\
[DEBUG] 处理上传文件: " + filename);
            databaseTool.processUserFile(filename);
        }
    }
}

class DatabaseTool {
    // 模拟文件存储路径
    private final String STORAGE_PATH = "/var/chat_uploads/";
    
    // 模拟数据库连接池
    private ConnectionPool connectionPool = new ConnectionPool();
    
    // 处理用户上传文件
    public void processUserFile(String filename) {
        // 1. 验证文件扩展名
        if (!isValidExtension(filename)) {
            System.out.println("[ERROR] 文件类型不合法");
            return;
        }
        
        // 2. 记录文件元数据到数据库
        String fileId = UUID.randomUUID().toString();
        String filePath = STORAGE_PATH + fileId + "_" + filename;
        
        if (!storeFileMetadata(fileId, filename, filePath)) {
            System.out.println("[ERROR] 文件元数据存储失败");
            return;
        }
        
        // 3. 执行系统命令处理文件（存在漏洞）
        try {
            // 漏洞点：直接拼接用户输入到系统命令
            String command = "file -b " + filePath + " | grep -q 'ASCII text'";
            System.out.println("[DEBUG] 执行命令: " + command);
            
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[CMD_OUTPUT] " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("[DEBUG] 命令执行结束 (退出码: " + exitCode + ")");
            
        } catch (Exception e) {
            System.out.println("[ERROR] 文件处理异常: " + e.getMessage());
        }
    }
    
    // 验证文件扩展名（存在绕过风险）
    private boolean isValidExtension(String filename) {
        String[] allowedExtensions = {"jpg", "png", "pdf"};
        String ext = filename.substring(filename.lastIndexOf('.') + 1);
        for (String allowed : allowedExtensions) {
            if (ext.equalsIgnoreCase(allowed)) {
                return true;
            }
        }
        return false;
    }
    
    // 模拟存储文件元数据
    private boolean storeFileMetadata(String fileId, String originalName, String filePath) {
        // 实际开发中会执行数据库操作
        System.out.println("[DEBUG] 存储文件元数据: " + fileId + ", " + originalName);
        return true; // 模拟成功
    }
}

class ConnectionPool {
    // 模拟数据库连接池实现
    public ConnectionPool() {
        System.out.println("[DEBUG] 初始化数据库连接池");
    }
}