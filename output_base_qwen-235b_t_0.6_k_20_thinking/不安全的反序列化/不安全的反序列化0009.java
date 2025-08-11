import java.io.*;
import java.util.*;

// 高抽象建模的流水线处理框架
interface DataProcessor {
    void process(DataRecord record);
}

abstract class RecordReader {
    public abstract DataRecord readNextRecord() throws IOException;
}

// 存在漏洞的反序列化实现
class SerializedDataReader extends RecordReader {
    private ObjectInputStream inputStream;

    public SerializedDataReader(InputStream input) throws IOException {
        this.inputStream = new ObjectInputStream(input);
    }

    @Override
    public DataRecord readNextRecord() throws IOException {
        try {
            // 不安全的反序列化操作
            return (DataRecord) inputStream.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("Invalid class in stream", e);
        }
    }
}

// 数据记录模型
class DataRecord implements Serializable {
    private String id;
    private Map<String, Object> metadata = new HashMap<>();

    public DataRecord(String id) {
        this.id = id;
    }

    // 模拟业务逻辑方法
    public void validate() {
        System.out.println("Validating record: " + id);
    }
}

// 恶意类示例（攻击者可构造的gadget链）
class MaliciousPayload implements Serializable {
    private String command;

    public MaliciousPayload(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        Runtime.getRuntime().exec(command);
    }
}

// 数据处理管道public class DataPipeline {
    private RecordReader reader;
    private List<DataProcessor> processors = new ArrayList<>();

    public DataPipeline(RecordReader reader) {
        this.reader = reader;
    }

    public void addProcessor(DataProcessor processor) {
        processors.add(processor);
    }

    public void startProcessing() throws IOException {
        try {
            DataRecord record;
            while ((record = reader.readNextRecord()) != null) {
                for (DataProcessor processor : processors) {
                    processor.process(record);
                }
            }
        } finally {
            reader.close();
        }
    }

    // 模拟主程序
    public static void main(String[] args) throws Exception {
        // 模拟恶意输入流
        byte[] maliciousData = createMaliciousStream();
        
        // 实际应用中可能来自网络或文件输入
        DataPipeline pipeline = new DataPipeline(
            new SerializedDataReader(new ByteArrayInputStream(maliciousData))
        );
        
        pipeline.addProcessor(record -> record.validate());
        pipeline.startProcessing();
    }

    // 构造恶意序列化数据（演示攻击面）
    private static byte[] createMaliciousStream() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(new MaliciousPayload("calc")); // 模拟执行任意命令
        out.flush();
        out.close();
        return bos.toByteArray();
    }
}