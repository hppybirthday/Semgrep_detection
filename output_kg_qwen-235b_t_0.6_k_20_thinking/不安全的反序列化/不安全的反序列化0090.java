package math.model;

import java.io.*;
import java.util.Base64;

/**
 * 数学模型基类
 */
public class MathModel implements Serializable {
    private String modelName;
    private double[] parameters;
    private transient int securityCheck = 0;

    public MathModel(String modelName, double[] parameters) {
        this.modelName = modelName;
        this.parameters = parameters;
    }

    // 模拟模型计算方法
    public void executeSimulation() {
        System.out.println("Running simulation: " + modelName);
        for (double param : parameters) {
            System.out.print(param + " ");
        }
        System.out.println();
    }

    // 模拟敏感操作
    private void checkIntegrity() {
        if (securityCheck != 123456) {
            throw new SecurityException("Model integrity check failed");
        }
    }

    /**
     * 不安全的反序列化实现
     */
    public static MathModel loadModel(String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            ois.close();
            return (MathModel) obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 安全的反序列化实现（对比参考）
     */
    public static MathModel safeLoadModel(String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            SecureObjectInputStream sois = new SecureObjectInputStream(new ByteArrayInputStream(data));
            Object obj = sois.readObject();
            sois.close();
            return (MathModel) obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 模拟主程序入口
    public static void main(String[] args) {
        // 模拟正常模型保存
        MathModel model = new MathModel("LinearRegression", new double[]{0.5, 1.2, 3.7});
        
        try {
            // 序列化模型
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(model);
            oos.close();
            
            // 模拟传输过程（攻击者可能篡改）
            String serializedData = Base64.getEncoder().encodeToString(bos.toByteArray());
            
            // 漏洞利用示例（假设攻击者修改了序列化数据）
            // 攻击者可能注入恶意代码或篡改模型参数
            System.out.println("[+] Loading model with unsafe deserialization...");
            MathModel loadedModel = MathModel.loadModel(serializedData);
            if (loadedModel != null) {
                loadedModel.executeSimulation();
            }
            
            // 安全加载方式演示
            System.out.println("[+] Loading model with safe deserialization...");
            MathModel safeModel = MathModel.safeLoadModel(serializedData);
            if (safeModel != null) {
                safeModel.executeSimulation();
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

/**
 * 安全反序列化流实现
 */
class SecureObjectInputStream extends ObjectInputStream {
    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        // 添加类白名单验证
        if (!desc.getName().equals("math.model.MathModel")) {
            throw new InvalidClassException("Restricted class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}