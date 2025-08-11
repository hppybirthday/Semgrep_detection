package com.example.dataprocess;

import java.io.*;
import java.util.Base64;

/**
 * 数据清洗服务原型
 * 快速实现反序列化数据处理功能
 */
public class DataCleaner {
    
    /**
     * 处理用户上传的序列化数据
     * @param encodedData Base64编码的序列化数据
     * @return 清洗后的数据记录
     * @throws Exception 反序列化异常
     */
    public DataRecord processSerializedData(String encodedData) throws Exception {
        // 模拟数据清洗流程
        System.out.println("[数据清洗流程启动]");
        
        // 1. Base64解码
        byte[] serializedData = Base64.getDecoder().decode(encodedData);
        
        // 2. 不安全的反序列化（漏洞点）
        try (InputStream is = new ByteArrayInputStream(serializedData);
             ObjectInputStream ois = new ObjectInputStream(is)) {
            
            // 直接反序列化不可信数据
            Object obj = ois.readObject();
            
            // 3. 类型转换
            if (obj instanceof DataRecord) {
                DataRecord record = (DataRecord) obj;
                // 4. 数据清洗逻辑（示例）
                record.sanitize();
                return record;
            }
        }
        
        throw new IllegalArgumentException("无效的数据格式");
    }

    /**
     * 数据记录类 - 可序列化的POJO
     */
    static class DataRecord implements Serializable {
        private static final long serialVersionUID = 1L;
        private String rawData;
        
        public DataRecord(String data) {
            this.rawData = data;
        }

        /**
         * 模拟数据清洗操作
         */
        public void sanitize() {
            System.out.println("清洗原始数据: " + rawData);
            // 实际清洗逻辑
            rawData = rawData.trim().replaceAll("[^a-zA-Z0-9]", "");
        }
        
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            // 模拟业务逻辑中的特殊处理
            in.defaultReadObject();
            // 潜在的二次攻击面
            if (rawData != null && rawData.contains("exec")) {
                System.out.println("发现特殊标记数据");
            }
        }
    }

    /**
     * 测试入口
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("使用示例: java DataCleaner [base64_data]");
            return;
        }
        
        DataCleaner cleaner = new DataCleaner();
        DataRecord result = cleaner.processSerializedData(args[0]);
        System.out.println("清洗结果: " + result.rawData);
    }
}