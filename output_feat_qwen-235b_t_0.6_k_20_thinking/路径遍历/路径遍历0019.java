import java.io.*;
import java.nio.file.*;
import java.util.*;

// 全局配置类
class Global {
    public static String getDownloadPath() {
        return "/var/taskmanager/uploads/";
    }
}

// 云存储服务接口
interface CloudStorage {
    void uploadFile(String filePath, byte[] content) throws Exception;
}

// 存在漏洞的文件服务实现
class VulnerableFileService implements CloudStorage {
    @Override
    public void uploadFile(String filePath, byte[] content) throws Exception {
        // 漏洞点：直接拼接路径
        Path fullPath = Paths.get(filePath);
        Files.write(fullPath, content, StandardOpenOption.CREATE);
    }
}

// 任务管理服务类
class TaskManagementService {
    private CloudStorage storage;

    public TaskManagementService(CloudStorage storage) {
        this.storage = storage;
    }

    // 模拟上传接口
    public void handleFileUpload(String fileName, byte[] content) throws Exception {
        // 漏洞触发点：未验证用户输入的文件名
        String basePath = Global.getDownloadPath();
        String targetPath = basePath + fileName;  // 路径拼接漏洞
        
        System.out.println("Saving to: " + targetPath);
        storage.uploadFile(targetPath, content);
    }
}

// 模拟攻击测试
public class PathTraversalDemo {
    public static void main(String[] args) {
        try {
            // 创建恶意文件名
            String maliciousFilename = "../../../../../tmp/evil.txt";
            byte[] payload = "Malicious content!".getBytes();
            
            // 初始化服务
            TaskManagementService service = new TaskManagementService(new VulnerableFileService());
            
            // 触发漏洞
            System.out.println("[+] 正常上传...");
            service.handleFileUpload("normal.txt", payload);
            
            System.out.println("\
[!] 触发路径遍历漏洞...");
            service.handleFileUpload(maliciousFilename, payload);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}