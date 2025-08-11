import java.io.*;
import java.util.Scanner;

class ModelData implements Serializable {
    private static final long serialVersionUID = 1L;
    public double[] weights;
    public int layers;
    
    public ModelData(double[] weights, int layers) {
        this.weights = weights;
        this.layers = layers;
    }
}

public class UnsafeModelLoader {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter model file path:");
        String filePath = scanner.nextLine();
        
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filePath)
            );
            ModelData model = (ModelData) ois.readObject();
            ois.close();
            
            System.out.println("Loaded model with " + model.layers + " layers");
            // 模拟使用模型进行预测
            double prediction = 0;
            for(double w : model.weights) {
                prediction += w * Math.random();
            }
            System.out.println("Prediction result: " + prediction);
            
        } catch (Exception e) {
            System.out.println("Failed to load model: " + e.getMessage());
        }
    }
}

// 恶意类示例（攻击者构造的payload）
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("calc.exe"); // 模拟执行恶意命令
    }
}