package com.example.crawler.domain;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * 网络爬虫任务实体（领域层）
 * 包含序列化敏感操作
 */
public class CrawlTask implements Serializable {
    private String url;
    private Map<String, Object> context = new HashMap<>();
    private transient CrawlResult result; // 非序列化结果

    public CrawlTask(String url) {
        this.url = url;
    }

    // 模拟从数据库反序列化任务
    public static CrawlTask restoreFromSnapshot(byte[] snapshot) {
        try {
            // 漏洞点：不安全的反序列化操作
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(snapshot)
            );
            return (CrawlTask) ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("恢复任务失败", e);
        }
    }

    // 模拟序列化存储任务
    public byte[] generateSnapshot() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(this);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("生成快照失败", e);
        }
    }

    // 模拟业务方法
    public void process() {
        System.out.println("爬取页面: " + url);
        // 实际爬取逻辑...
    }
}

// 基础设施层：模拟数据访问对象
package com.example.crawler.infrastructure;

import com.example.crawler.domain.CrawlTask;
import java.util.Base64;

public class TaskRepository {
    // 模拟数据库存储
    private static byte[] storedSnapshot;

    public void saveTask(CrawlTask task) {
        storedSnapshot = task.generateSnapshot();
        System.out.println("任务已存储（Base64）: " + Base64.getEncoder().encodeToString(storedSnapshot));
    }

    public CrawlTask restoreTask() {
        // 漏洞传播路径：恶意数据可能被注入
        return CrawlTask.restoreFromSnapshot(storedSnapshot);
    }
}

// 应用层：爬虫服务
package com.example.crawler.application;

import com.example.crawler.domain.CrawlTask;
import com.example.crawler.infrastructure.TaskRepository;

public class CrawlerService {
    private TaskRepository taskRepo = new TaskRepository();

    // 模拟处理用户提交的爬虫任务
    public void handleUserTask(String url) {
        CrawlTask task = new CrawlTask(url);
        taskRepo.saveTask(task);
        
        // 模拟后续处理
        CrawlTask restored = taskRepo.restoreTask();
        restored.process();
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            new CrawlerService().handleUserTask(args[0]);
        } else {
            System.out.println("Usage: java CrawlerService <URL>");
        }
    }
}