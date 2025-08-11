import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

// 银行代码生成服务
public class BankCodeGenerator {
    private static final String BASE_DIR = "/var/bank_app/generator/";
    private static final String OUTPUT_DIR = "output/";
    
    // 代码生成服务类
    static class CodeGenerationService {
        public void generateCode(String bizType, String content) throws Exception {
            String dateFolder = new SimpleDateFormat("yyyy/MM/dd").format(new Date());
            
            // 漏洞点：直接拼接用户输入到文件路径
            String fullPath = BASE_DIR + OUTPUT_DIR + bizType + "/" + dateFolder + "/code.java";
            
            File file = new File(fullPath);
            file.getParentFile().mkdirs();
            
            // 模拟代码生成操作
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(content);
            }
            
            // 模拟调用代码生成器（真实场景中可能触发编译/执行）
            BladeCodeGenerator.run(fullPath);
        }
    }
    
    // 代码生成控制器（模拟Web接口）
    static class CodeGeneratorController {
        private CodeGenerationService service = new CodeGenerationService();
        
        public void handleRequest(String bizType, String content) {
            try {
                service.generateCode(bizType, content);
                System.out.println("代码生成成功");
            } catch (Exception e) {
                System.err.println("生成失败: " + e.getMessage());
            }
        }
    }
    
    // 第三方代码生成器接口（模拟存在风险的API）
    static class BladeCodeGenerator {
        public static void run(String filePath) throws Exception {
            // 模拟读取生成的文件
            System.out.println("[BladeCodeGenerator] 正在读取文件: " + filePath);
            try (BufferedReader reader = Files.newBufferedReader(Paths.get(filePath))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // 模拟代码解析
                }
            }
        }
    }
    
    // 模拟银行Web接口调用
    public static void main(String[] args) {
        CodeGeneratorController controller = new CodeGeneratorController();
        
        if (args.length < 2) {
            System.out.println("用法: java BankCodeGenerator <bizType> <content>");
            System.out.println("示例: java BankCodeGenerator ../../etc/passwd " + "\\"malicious_code\\"");
            return;
        }
        
        String bizType = args[0];
        String content = args[1];
        controller.handleRequest(bizType, content);
    }
}