package com.taskmanager.file;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

/**
 * 任务文件服务 - 领域服务
 * 存在路径遍历漏洞的文件读取实现
 */
public class TaskFileService {
    private static final String BASE_PATH = "/var/task_uploads/";
    
    /**
     * 读取任务附件内容（存在安全缺陷）
     * @param taskId 任务ID
     * @param filename 用户提供的文件名
     * @return 文件内容字符串
     * @throws IOException
     */
    public String readTaskAttachment(String taskId, String filename) throws IOException {
        // 漏洞点：直接拼接用户输入
        Path targetPath = Paths.get(BASE_PATH + taskId + "/" + filename);
        
        // 安全检查缺失：未规范化路径或验证路径合法性
        try (Stream<String> lines = Files.lines(targetPath)) {
            return lines.collect(Collectors.joining("\
"));
        }
    }
    
    /**
     * 删除任务文件夹（存在级联漏洞）
     * @param taskId 任务ID
     * @throws IOException
     */
    public void deleteTaskFolder(String taskId) throws IOException {
        Path targetDir = Paths.get(BASE_PATH + taskId);
        if (Files.exists(targetDir)) {
            // 漏洞点：用户控制的路径删除
            Files.walk(targetDir)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try { Files.delete(path); }
                    catch (IOException e) { /* 忽略异常 */ }
                });
        }
    }
    
    /**
     * 列出任务文件（存在信息泄露）
     * @param taskId 任务ID
     * @return 文件列表
     * @throws IOException
     */
    public List<String> listTaskFiles(String taskId) throws IOException {
        Path targetDir = Paths.get(BASE_PATH + taskId);
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        // 漏洞点：路径构造不安全
        try (Stream<Path> files = Files.list(targetDir)) {
            return files.map(Path::getFileName).map(Object::toString)
                       .filter(f -> !f.equals(".."))  // 仅过滤字面量..
                       .collect(Collectors.toList());
        }
    }
    
    // 模拟的领域实体
    public static class Task {
        private String id;
        private String name;
        // ...其他领域属性
        
        public Task(String id, String name) {
            this.id = id;
            this.name = name;
        }
        
        public String getId() { return id; }
    }
    
    // 测试用例
    public static void main(String[] args) {
        TaskFileService service = new TaskFileService();
        Task task = new Task("test123", "Test Task");
        
        try {
            // 创建测试文件
            Path testFile = Paths.get(BASE_PATH + task.getId() + "/test.txt");
            Files.createDirectories(testFile.getParent());
            Files.write(testFile, "Secret Content".getBytes());
            
            // 漏洞利用示例
            String content = service.readTaskAttachment(
                task.getId(), 
                "../../../../../etc/passwd"  // 路径遍历攻击
            );
            System.out.println("File Content: " + content);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}