import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

// 数学模型执行器
class ModelExecutor {
    // 执行数学模型计算（存在漏洞的实现）
    public void executeModel(String parameter) {
        try {
            // 使用Runtime执行外部Python脚本
            String command = "python3 math_model.py " + parameter;
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取输出结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            System.out.println("模型输出：");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            // 错误输出处理
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }
            
            process.waitFor();
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}

// 数学模型管理器
class ModelManager {
    private ModelExecutor executor = new ModelExecutor();
    
    // 接收用户输入并执行模型
    public void runModel() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入模型参数（示例：1000）：");
        String parameter = scanner.nextLine();
        
        System.out.println("正在执行数学模型...");
        executor.executeModel(parameter);
    }
}

// 主程序入口
public class Main {
    public static void main(String[] args) {
        System.out.println("=== 数学建模与仿真系统 ===");
        System.out.println("功能：执行数值模拟计算");
        System.out.println("开发者：张三（测试版）");
        
        ModelManager manager = new ModelManager();
        manager.runModel();
    }
}