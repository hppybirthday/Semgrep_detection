package com.example.crawler.domain;

import java.io.*;
import java.util.Date;

// 领域模型：爬虫任务
public class CrawlTask implements Serializable {
    private String url;
    private Date scheduledTime;
    private transient boolean isProcessed = false;

    public CrawlTask(String url) {
        this.url = url;
        this.scheduledTime = new Date();
    }

    // 模拟处理逻辑
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        isProcessed = false; // 反序列化后重置状态
    }
}

// 基础设施层：任务存储仓库
class CrawlTaskRepository {
    // 存在漏洞的反序列化方法
    public CrawlTask loadTask(InputStream inputStream) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(inputStream)) {
            // 直接反序列化不可信数据
            return (CrawlTask) in.readObject();
        }
    }

    public void saveTask(CrawlTask task, OutputStream outputStream) throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(outputStream)) {
            out.writeObject(task);
        }
    }
}

// 应用服务：爬虫管理器
public class CrawlTaskManager {
    private final CrawlTaskRepository repository = new CrawlTaskRepository();

    // 模拟从不可信源加载任务
    public CrawlTask importTask(byte[] data) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            // 危险的反序列化操作
            return (CrawlTask) ois.readObject();
        }
    }

    public static void main(String[] args) {
        // 模拟正常任务序列化
        CrawlTaskManager manager = new CrawlTaskManager();
        CrawlTask task = new CrawlTask("http://example.com");
        
        try {
            // 模拟攻击者注入恶意序列化数据
            byte[] maliciousData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("malicious_task.ser"));
            manager.importTask(maliciousData); // 触发漏洞
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}