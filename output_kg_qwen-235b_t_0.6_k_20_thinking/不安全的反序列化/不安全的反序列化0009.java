package com.example.bigdata.processor;

import java.io.*;
import java.util.*;

/**
 * 高抽象建模的大数据处理管道
 */
public interface DataProcessor {
    Object process(SerializedData data) throws Exception;
}

abstract class BaseDataProcessor implements DataProcessor {
    @Override
    public Object process(SerializedData data) throws Exception {
        if (data == null || data.getContent() == null) {
            throw new IllegalArgumentException("Empty data");
        }
        return handle(deserialize(data.getContent()));
    }

    protected abstract Object handle(Object obj);

    private Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return ois.readObject(); // 不安全的反序列化操作
        }
    }
}

class DefaultProcessor extends BaseDataProcessor {
    @Override
    protected Object handle(Object obj) {
        if (obj instanceof Map) {
            return "Map size: " + ((Map<?,?>)obj).size();
        }
        return "Processed: " + obj.toString();
    }
}

/**
 * 数据传输载体
 */
class SerializedData implements Serializable {
    private byte[] content;
    // 模拟大数据分片传输
    private List<String> metadata = new ArrayList<>();

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}

/**
 * 工厂模式构建处理管道
 */
class ProcessorFactory {
    static DataProcessor create() {
        return new DefaultProcessor();
    }
}

/**
 * 模拟大数据服务端点
 */
public class DataProcessingService {
    public static void main(String[] args) {
        try {
            // 模拟接收网络传输的序列化数据
            SerializedData data = new SerializedData();
            data.setContent(getMaliciousPayload()); // 恶意数据注入点
            
            DataProcessor processor = ProcessorFactory.create();
            System.out.println("Processing result: " + processor.process(data));
            
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }

    // 模拟攻击者构造的恶意负载
    private static byte[] getMaliciousPayload() throws IOException {
        // 实际攻击中可能包含Gadget链
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(new HashMap<>()); // 正常数据示例
        }
        return baos.toByteArray();
    }
}