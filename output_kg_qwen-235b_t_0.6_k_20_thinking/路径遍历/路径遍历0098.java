package com.example.taskmanager.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * 任务附件服务
 * 高抽象建模风格
 * 存在路径遍历漏洞的示例实现
 */
public class TaskAttachmentService {
    private final String baseStoragePath;

    public TaskAttachmentService(String configPath) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath)) {
            props.load(fis);
            this.baseStoragePath = props.getProperty("storage.path");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load storage config", e);
        }
    }

    /**
     * 下载任务附件
     * 漏洞点：未对用户输入的文件名进行路径校验
     * @param taskId 任务ID
     * @param fileName 用户提供的文件名
     * @return 文件字节流
     * @throws IOException
     */
    public byte[] downloadAttachment(String taskId, String fileName) throws IOException {
        // 构建存储路径：baseStoragePath + taskId + fileName
        Path attachmentPath = Paths.get(baseStoragePath, taskId, fileName);
        File file = new File(attachmentPath.toString());
        
        // 漏洞体现：直接使用用户输入构造文件路径
        // 攻击者可通过"../../../etc/passwd"等路径穿越访问任意文件
        if (!file.exists()) {
            throw new IOException("File not found");
        }

        return readAllBytes(file);
    }

    /**
     * 上传任务附件
     * 漏洞点：未限制文件存储路径
     * @param taskId 任务ID
     * @param fileName 文件名
     * @param content 文件内容
     * @throws IOException
     */
    public void uploadAttachment(String taskId, String fileName, byte[] content) throws IOException {
        Path attachmentPath = Paths.get(baseStoragePath, taskId, fileName);
        File file = new File(attachmentPath.toString());
        
        // 漏洞体现：允许用户控制文件存储路径
        // 攻击者可通过"../../../tmp/exploit.txt"写入任意位置
        writeBytesToFile(file, content);
    }

    // 模拟文件读取方法
    private byte[] readAllBytes(File file) throws IOException {
        // 实际应使用NIO Files.readAllBytes
        byte[] content = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(content);
        }
        return content;
    }

    // 模拟文件写入方法
    private void writeBytesToFile(File file, byte[] content) throws IOException {
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
    }

    // 配置示例：
    // storage.path=/var/task_attachments
    // 攻击示例：
    // fileName="../../../etc/shadow" -> 读取系统密码文件
    // fileName="../../../../tmp/exploit.sh" -> 写入webshell
}

// 控制器层示例（简化）
class TaskAttachmentController {
    private final TaskAttachmentService service;

    public TaskAttachmentController(TaskAttachmentService service) {
        this.service = service;
    }

    // 模拟HTTP接口
    public byte[] handleDownload(String taskId, String fileName) {
        try {
            return service.downloadAttachment(taskId, fileName);
        } catch (IOException e) {
            throw new RuntimeException("Download failed: " + e.getMessage());
        }
    }
}