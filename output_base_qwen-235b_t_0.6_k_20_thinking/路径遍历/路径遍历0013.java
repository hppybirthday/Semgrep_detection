import java.io.*;
import java.util.Scanner;

// 数学模型参数类
class ModelParams {
    double[] coefficients;
    int iterations;
    
    public ModelParams(double[] coefficients, int iterations) {
        this.coefficients = coefficients;
        this.iterations = iterations;
    }
}

// 仿真引擎类
class Simulation {
    private ModelParams params;
    
    public Simulation(ModelParams params) {
        this.params = params;
    }
    
    public void runSimulation() {
        System.out.println("Running simulation with " + params.iterations + " iterations");
        // 模拟计算过程
        for(int i=0; i<params.coefficients.length; i++) {
            System.out.println("Coefficient " + i + ": " + params.coefficients[i]);
        }
    }
}

// 模型加载器类（存在漏洞）
class ModelLoader {
    public ModelParams loadModel(String filename) throws IOException {
        // 路径遍历漏洞点：直接拼接用户输入
        File file = new File("./models/" + filename);
        
        // 检查文件是否存在
        if(!file.exists()) {
            throw new FileNotFoundException("Model file not found: " + filename);
        }
        
        // 读取文件内容
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String[] coeffStr = reader.readLine().split(",");
        double[] coefficients = new double[coeffStr.length];
        for(int i=0; i<coeffStr.length; i++) {
            coefficients[i] = Double.parseDouble(coeffStr[i]);
        }
        
        int iterations = Integer.parseInt(reader.readLine());
        reader.close();
        
        return new ModelParams(coefficients, iterations);
    }
}

// 主程序
public class MathModelSimulation {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter model filename: ");
        String filename = scanner.nextLine();
        
        try {
            ModelLoader loader = new ModelLoader();
            ModelParams params = loader.loadModel(filename);
            Simulation sim = new Simulation(params);
            sim.runSimulation();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}