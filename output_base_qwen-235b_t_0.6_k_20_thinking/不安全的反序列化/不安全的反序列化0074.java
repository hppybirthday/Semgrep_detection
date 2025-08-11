import java.io.*;
import java.util.*;

// 模拟数据清洗服务
public class DataCleaner {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java DataCleaner <file_path>");
            return;
        }
        
        try {
            DataCleaningService service = new DataCleaningService();
            List<Record> cleanedData = service.processSerializedData(args[0]);
            System.out.println("Data cleaned successfully. Record count: " + cleanedData.size());
        } catch (Exception e) {
            System.err.println("Data processing failed: " + e.getMessage());
        }
    }
}

class DataCleaningService {
    public List<Record> processSerializedData(String filePath) throws IOException, ClassNotFoundException {
        List<Record> result = new ArrayList<>();
        
        if (!new File(filePath).exists()) {
            throw new FileNotFoundException("Input file not found: " + filePath);
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 危险操作：直接反序列化不可信数据
            Object raw = ois.readObject();
            
            if (raw instanceof List<?>) {
                for (Object item : (List<?>) raw) {
                    if (item instanceof Record) {
                        // 模拟数据清洗逻辑
                        Record record = (Record) item;
                        if (record.isValid() && !record.isDuplicate()) {
                            result.add(record);
                        }
                    }
                }
            }
        }
        
        return result;
    }
}

class Record implements Serializable {
    private String data;
    private transient boolean processed;
    
    public Record(String data) {
        this.data = data;
        this.processed = false;
    }
    
    public boolean isValid() {
        return data != null && !data.trim().isEmpty();
    }
    
    public boolean isDuplicate() {
        // 模拟复杂业务逻辑
        return data.hashCode() % 10 == 0;
    }
    
    // 恶意构造的readObject方法（演示攻击面）
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            in.defaultReadObject();
            // 模拟恶意代码执行
            if (data != null && data.contains("malicious")) {
                Runtime.getRuntime().exec("calc"); // 模拟RCE攻击
            }
        } catch (Exception e) {
            throw new IOException("Deserialization error: " + e.getMessage());
        }
    }
}