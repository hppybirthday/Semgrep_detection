import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * 模拟机器学习模型训练服务
 * 开发者错误地信任用户输入并尝试防御特殊字符
 */
public class VulnerableMLApp {
    private static final Logger logger = Logger.getLogger("MLAppLogger");

    // 模拟不充分的输入验证
    static class InputValidator {
        boolean validateInput(String input) {
            // 错误地使用黑名单策略
            if (input.contains("&") || input.contains("|") || input.contains("&&")) {
                logger.warning("Invalid input detected");
                return false;
            }
            return true;
        }
    }

    // 执行预处理脚本（存在漏洞）
    void runPreprocessing(String dataset, String params) {
        try {
            // 漏洞点：直接拼接用户输入
            String command = "python3 preprocess.py --dataset=" + dataset + " --params=" + params;
            Process process = Runtime.getRuntime().exec(command);
            
            // 输出脚本执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Script Output] " + line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        VulnerableMLApp app = new VulnerableMLApp();
        InputValidator validator = new InputValidator();
        
        System.out.println("=== ML Model Training Service ===");
        System.out.print("Enter dataset name: ");
        String dataset = scanner.nextLine();
        
        System.out.print("Enter training parameters: ");
        String params = scanner.nextLine();
        
        // 错误的验证逻辑（可被绕过）
        if (!validator.validateInput(dataset) || !validator.validateInput(params)) {
            System.out.println("Input validation failed!");
            return;
        }
        
        System.out.println("Running preprocessing...");
        app.runPreprocessing(dataset, params);
        System.out.println("Preprocessing completed.");
    }
}