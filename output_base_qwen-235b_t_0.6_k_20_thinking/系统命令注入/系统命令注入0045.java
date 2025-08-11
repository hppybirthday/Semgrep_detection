import java.io.*;
import java.util.Scanner;

public class DynamicModelExecutor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter mathematical expression for simulation:");
        String userInput = scanner.nextLine();
        
        try {
            // 使用元编程风格动态生成Python脚本执行数学运算
            String pythonScript = "def calculate():\
    try:\
        result = " + userInput + "\
        print(f'Result: {result}')\
    except Exception as e:\
        print(f'Error: {str(e)}')\
if __name__ == '__main__':\
    calculate()";
            
            // 将Python脚本写入临时文件
            File tmpScript = File.createTempFile("model_", ".py");
            tmpScript.deleteOnExit();
            BufferedWriter writer = new BufferedWriter(new FileWriter(tmpScript));
            writer.write(pythonScript);
            writer.close();
            
            // 执行系统命令调用Python解释器
            ProcessBuilder pb = new ProcessBuilder("python3", tmpScript.getAbsolutePath());
            Process process = pb.start();
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("\
Simulation completed with exit code: " + exitCode);
            
        } catch (Exception e) {
            System.err.println("Simulation failed: " + e.getMessage());
        }
    }
}