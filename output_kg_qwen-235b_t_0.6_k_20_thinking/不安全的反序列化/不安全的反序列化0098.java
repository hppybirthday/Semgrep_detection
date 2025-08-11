package bigdata.processor;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.logging.Logger;

/**
 * 元编程风格的大数据处理框架
 * 模拟分布式计算任务反序列化场景
 */
public class MetaDataProcessor {
    private static final Logger logger = Logger.getLogger(MetaDataProcessor.class.getName());

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: MetaDataProcessor <file-path>");
            return;
        }
        try {
            logger.info("Starting data processing...");
            processData(args[0]);
            logger.info("Processing completed successfully.");
        } catch (Exception e) {
            logger.severe("Processing failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void processData(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            logger.info("Reading object from " + filePath);
            Object obj = ois.readObject();
            logger.info("Object read successfully: " + obj.getClass().getName());

            if (obj instanceof Processable) {
                Processable processable = (Processable) obj;
                logger.info("Executing process method...");
                processable.process();
                logger.info("Process method executed.");
            } else {
                logger.warning("Unsupported data type: " + obj.getClass().getName());
            }
        }
    }

    public static void validateData(Processable data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
    }
}

interface Processable extends Serializable {
    void process();
}

class DataPacket implements Processable {
    private String content;
    private int priority;

    public DataPacket(String content, int priority) {
        this.content = content;
        this.priority = priority;
    }

    public void process() {
        System.out.println("[" + priority + "] Processing data packet: " + content);
        if ("critical".equals(content)) {
            System.out.println("Executing critical workflow...");
        }
    }

    public String getContent() { return content; }
    public int getPriority() { return priority; }
}

class AdvancedDataPacket extends DataPacket {
    private String metadata;

    public AdvancedDataPacket(String content, int priority, String metadata) {
        super(content, priority);
        this.metadata = metadata;
    }

    public void process() {
        System.out.println("Processing advanced packet with metadata: " + metadata);
        super.process();
    }
}