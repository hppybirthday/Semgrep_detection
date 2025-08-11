import java.io.*;
import java.util.*;

public class DataCleaner {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java DataCleaner <input_file>");
            return;
        }

        String filePath = args[0];
        List<String> cleanedData = new ArrayList<>();
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            Object rawObject = ois.readObject();
            
            // 模拟数据清洗流程
            if (rawObject instanceof Map) {
                Map<?, ?> rawDataMap = (Map<?, ?>) rawObject;
                for (Map.Entry<?, ?> entry : rawDataMap.entrySet()) {
                    String key = sanitize(String.valueOf(entry.getKey()));
                    String value = sanitize(String.valueOf(entry.getValue()));
                    cleanedData.add(key + ":" + value);
                }
            } else if (rawObject instanceof String[]) {
                for (String s : (String[]) rawObject) {
                    cleanedData.add(sanitize(s));
                }
            } else {
                cleanedData.add(sanitize(rawObject.toString()));
            }

            // 输出清洗结果
            System.out.println("Cleaned Data:");
            for (String s : cleanedData) {
                System.out.println(s);
            }

        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String sanitize(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9\\s]", "");
    }
}

// 漏洞利用示例类（攻击者构造的恶意类）
class MaliciousPayload implements Serializable {
    private String command;
    
    public MaliciousPayload(String cmd) {
        this.command = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟反序列化时执行任意命令
        Runtime.getRuntime().exec(command);
    }
}