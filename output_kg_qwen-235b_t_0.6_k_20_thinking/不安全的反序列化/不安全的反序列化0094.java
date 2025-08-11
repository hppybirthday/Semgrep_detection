package com.example.crawler.core;

import java.io.*;
import java.util.Base64;

/**
 * 网络爬虫核心领域模型
 */
public class CrawlerTask implements Serializable {
    private String url;
    private int priority;

    public CrawlerTask(String url, int priority) {
        this.url = url;
        this.priority = priority;
    }

    public void execute() {
        System.out.println("Crawling: " + url + " with priority " + priority);
    }
}

// 应用服务层
package com.example.crawler.application;

import com.example.crawler.core.CrawlerTask;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.Base64;

@Service
public class CrawlerService {
    
    /**
     * 从不可信来源加载序列化任务
     * 存在不安全反序列化漏洞
     */
    public void loadSerializedTask(String encodedTask) {
        try {
            byte[] data = Base64.getDecoder().decode(encodedTask);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            // 漏洞点：直接反序列化不可信数据
            CrawlerTask task = (CrawlerTask) ois.readObject();
            task.execute();
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 模拟接收外部输入的爬虫任务
     */
    public void handleExternalInput(String userInput) {
        // 模拟从HTTP请求参数、消息队列等来源获取的序列化数据
        loadSerializedTask(userInput);
    }
}

// 领域服务接口
package com.example.crawler.domain.service;

import com.example.crawler.core.CrawlerTask;

public interface CrawlerDomainService {
    void scheduleTask(CrawlerTask task);
}

// 基础设施层
package com.example.crawler.infrastructure.persistence;

import com.example.crawler.core.CrawlerTask;

import java.io.*;

public class TaskSerializer {
    /**
     * 漏洞点：不安全的反序列化方法
     */
    public static CrawlerTask deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (CrawlerTask) ois.readObject();
        }
    }

    public static byte[] serialize(CrawlerTask task) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(task);
            return bos.toByteArray();
        }
    }
}

// 控制器层
package com.example.crawler.controller;

import com.example.crawler.application.CrawlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class CrawlerTaskController {
    
    @Autowired
    private CrawlerService crawlerService;

    /**
     * 漏洞端点：接收Base64编码的序列化对象
     */
    @PostMapping("/load")
    public String loadTask(@RequestParam String taskData) {
        // 模拟攻击面：攻击者可通过taskData参数注入恶意序列化数据
        crawlerService.handleExternalInput(taskData);
        return "Task loaded";
    }
}