import java.io.*;
import java.util.*;

interface DataProcessor {
    String processData(String inputPath) throws IOException;
}

class HDFSDataProcessor implements DataProcessor {
    private final String baseDirectory = "/user/data/";
    
    @Override
    public String processData(String inputPath) throws IOException {
        // 构造文件路径时未验证输入合法性
        File file = new File(baseDirectory + inputPath);
        
        // 检查文件是否存在（存在安全缺陷）
        if (!file.exists()) {
            throw new FileNotFoundException("File not found: " + inputPath);
        }
        
        // 存在路径遍历风险的文件读取
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

class DataProcessingPipeline {
    private DataProcessor processor;
    
    public DataProcessingPipeline(DataProcessor processor) {
        this.processor = processor;
    }
    
    public String executeProcessing(String inputPath) throws IOException {
        // 调用处理器执行数据处理
        return processor.processData(inputPath);
    }
}

public class Main {
    public static void main(String[] args) {
        try {
            // 模拟用户输入
            String userInput = args.length > 0 ? args[0] : "sample_data.txt";
            
            // 创建处理器实例
            DataProcessor processor = new HDFSDataProcessor();
            // 创建处理流水线
            DataProcessingPipeline pipeline = new DataProcessingPipeline(processor);
            
            // 执行处理并输出结果
            String result = pipeline.executeProcessing(userInput);
            System.out.println("Processed content:\
" + result);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}