import java.io.*;
import java.nio.file.*;
import java.util.*;

// 全局配置类
class Global {
    private static String downloadPath = "/var/www/tasks/";
    
    public static String getDownloadPath() {
        return downloadPath;
    }
}

// 文件存储服务
class StorageService {
    // 存储文件（存在漏洞）
    public boolean store(String fileName, byte[] content) {
        try {
            // 路径拼接漏洞点
            File file = new File(Global.getDownloadPath() + fileName);
            
            // 创建父目录（可能创建任意路径）
            file.getParentFile().mkdirs();
            
            // 写入文件内容
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(content);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // 删除文件（存在漏洞）
    public boolean delete(String fileName) {
        try {
            // 路径拼接漏洞点
            File file = new File(Global.getDownloadPath() + fileName);
            return file.delete();
        } catch (Exception e) {
            return false;
        }
    }
}

// 任务实体类
class Task {
    private String id;
    private String description;
    
    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }
    
    // 获取任务附件路径
    public String getAttachmentPath() {
        return "task_" + id + ".dat";
    }
}

// 任务控制器（API接口）
public class TaskController {
    private StorageService storage = new StorageService();
    
    // 上传任务附件（漏洞触发点）
    public String uploadAttachment(String taskId, String userInput, byte[] content) {
        Task task = new Task(taskId, "Sample task");
        
        // 危险的路径拼接：直接使用用户输入
        String filePath = task.getAttachmentPath() + "_" + userInput;
        
        if (storage.store(filePath, content)) {
            return "File uploaded to: " + filePath;
        } else {
            return "Upload failed";
        }
    }
    
    // 删除任务附件（漏洞触发点）
    public String deleteAttachment(String userInput) {
        // 危险的路径拼接：直接使用用户输入
        String filePath = "task_123.dat_" + userInput;
        
        if (storage.delete(filePath)) {
            return "File deleted: " + filePath;
        } else {
            return "Delete failed";
        }
    }
    
    public static void main(String[] args) {
        TaskController controller = new TaskController();
        
        // 测试用例（正常使用）
        System.out.println("--- 正常使用 ---");
        byte[] content = "Normal file content".getBytes();
        System.out.println(controller.uploadAttachment("456", "normal.txt", content));
        
        // 恶意测试用例（路径遍历攻击）
        System.out.println("\
--- 路径遍历攻击 ---");
        byte[] evilContent = "Evil content".getBytes();
        System.out.println(controller.uploadAttachment("789", "../../etc/passwd", evilContent));
        System.out.println(controller.deleteAttachment("../../etc/shadow"));
    }
}