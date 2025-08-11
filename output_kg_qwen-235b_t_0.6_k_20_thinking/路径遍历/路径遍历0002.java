import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

// 任务类
class Task {
    private String id;
    private String description;
    private List<Attachment> attachments = new ArrayList<>();

    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }

    public void addAttachment(Attachment attachment) {
        attachments.add(attachment);
    }

    public List<Attachment> getAttachments() {
        return attachments;
    }

    public String getId() {
        return id;
    }
}

// 附件类
class Attachment {
    private String id;
    private String fileName;
    private String filePath;

    public Attachment(String id, String fileName, String filePath) {
        this.id = id;
        this.fileName = fileName;
        this.filePath = filePath;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFilePath() {
        return filePath;
    }
}

// 文件管理服务类
class TaskAttachmentService {
    private static final String STORAGE_DIR = "./task_attachments/";

    // 模拟存储附件（存在漏洞的版本）
    public void storeAttachment(String taskId, String fileName) {
        try {
            // 危险操作：直接拼接用户输入的文件名
            Path targetPath = Paths.get(STORAGE_DIR + taskId + "/" + fileName);
            
            // 创建存储目录
            Files.createDirectories(targetPath.getParent());
            
            // 创建并写入文件（模拟存储过程）
            Files.write(targetPath, "Mock content".getBytes());
            
            System.out.println("Stored at: " + targetPath.toAbsolutePath());
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 下载附件时的路径遍历漏洞（核心问题）
    public byte[] downloadAttachment(String taskId, String fileName) {
        try {
            // 漏洞点：直接拼接用户输入的文件名
            File file = new File(STORAGE_DIR + taskId + "/" + fileName);
            
            if (!file.exists()) {
                return "File not found".getBytes();
            }
            
            // 读取文件内容（可能读取任意文件）
            return Files.readAllBytes(file.toPath());
            
        } catch (IOException e) {
            return e.getMessage().getBytes();
        }
    }
}

// 任务管理系统入口
public class TaskManagementSystem {
    public static void main(String[] args) {
        TaskAttachmentService service = new TaskAttachmentService();
        
        // 创建任务并存储附件
        Task task = new Task("task001", "Security Audit Report");
        
        // 正常使用场景
        System.out.println("--- 正常使用场景 ---");
        service.storeAttachment(task.getId(), "report.pdf");
        System.out.println(new String(service.downloadAttachment(task.getId(), "report.pdf")));
        
        // 恶意攻击场景（路径遍历）
        System.out.println("\
--- 攻击场景演示 ---");
        System.out.println("尝试读取系统文件 /etc/passwd：");
        // 注意：实际攻击中可能需要根据存储路径结构调整../数量
        byte[] result = service.downloadAttachment(task.getId(), "../../../../../etc/passwd");
        System.out.println(new String(result));
    }
}