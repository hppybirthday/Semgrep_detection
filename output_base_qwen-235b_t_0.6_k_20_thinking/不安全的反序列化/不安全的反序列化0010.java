import java.io.*;
import java.util.*;

class DataRecord implements Serializable {
    private static final long serialVersionUID = 1L;
    private String rawData;
    private Map<String, Object> metadata;

    public DataRecord(String rawData) {
        this.rawData = rawData;
        this.metadata = new HashMap<>();
    }

    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }

    public String getRawData() {
        return rawData;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }
}

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java DataCleaner <file_path>");
            return;
        }

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[0]))) {
            DataRecord record = (DataRecord) ois.readObject();
            System.out.println("[+] Raw Data: " + record.getRawData());
            System.out.println("[+] Metadata Size: " + record.getMetadata().size());
            
            // 模拟数据清洗过程
            String cleanedData = record.getRawData().trim().replaceAll("\\\\s+", " ");
            System.out.println("[+] Cleaned Data: " + cleanedData);
            
            // 潜在危险操作：遍历metadata（可能触发恶意逻辑）
            for (Map.Entry<String, Object> entry : record.getMetadata().entrySet()) {
                System.out.println("Metadata: " + entry.getKey() + "=" + entry.getValue());
            }
            
        } catch (Exception e) {
            System.err.println("[-] Error processing file: " + e.getMessage());
        }
    }

    // 模拟数据清洗工具方法
    private static String sanitizeInput(String input) {
        return input == null ? "" : input.replaceAll("[^a-zA-Z0-9 ]", "");
    }
}