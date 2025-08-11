package com.bigdata.processor;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * 高抽象建模风格的大数据处理系统
 * 包含分布式任务处理框架的核心组件
 */
public class VulnerableDataProcessor {

    // 任务接口定义
    public interface DataProcessingTask extends Serializable {
        void execute();
        String getTaskId();
    }

    // 具体任务实现
    public static class DataAnalysisTask implements DataProcessingTask {
        private final String taskId;
        private final String query;

        public DataAnalysisTask(String taskId, String query) {
            this.taskId = taskId;
            this.query = query;
        }

        @Override
        public void execute() {
            System.out.println("Executing analysis task " + taskId + ": " + query);
            // 模拟实际数据分析逻辑
        }

        @Override
        public String getTaskId() {
            return taskId;
        }
    }

    // 分布式任务接收器
    public static class TaskReceiver {
        private final ExecutorService executor = Executors.newFixedThreadPool(4);

        // 模拟接收网络传输的序列化任务
        public void receiveTask(byte[] serializedTask) {
            executor.submit(() -> {
                try {
                    // 漏洞点：直接反序列化不可信数据
                    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedTask));
                    DataProcessingTask task = (DataProcessingTask) ois.readObject();
                    task.execute();
                } catch (Exception e) {
                    System.err.println("Task execution failed: " + e.getMessage());
                }
            });
        }

        public void shutdown() {
            executor.shutdown();
        }
    }

    // 模拟攻击者构造的恶意任务
    public static class MaliciousTask implements DataProcessingTask {
        @Override
        public void execute() {
            // 恶意代码执行点
            try {
                Runtime.getRuntime().exec("calc");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public String getTaskId() {
            return "malicious-0day";
        }
    }

    // 模拟测试主类
    public static void main(String[] args) {
        TaskReceiver receiver = new TaskReceiver();
        
        // 正常任务示例
        DataProcessingTask normalTask = new DataAnalysisTask("task-001", "SELECT * FROM logs");
        
        // 模拟网络传输
        byte[] serializedNormal = serializeTask(normalTask);
        receiver.receiveTask(serializedNormal);
        
        // 恶意任务模拟
        DataProcessingTask evilTask = new MaliciousTask();
        byte[] serializedEvil = serializeTask(evilTask);
        receiver.receiveTask(serializedEvil);
        
        receiver.shutdown();
    }

    // 序列化辅助方法
    private static byte[] serializeTask(DataProcessingTask task) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(task);
            oos.flush();
            oos.close();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Serialization failed", e);
        }
    }
}