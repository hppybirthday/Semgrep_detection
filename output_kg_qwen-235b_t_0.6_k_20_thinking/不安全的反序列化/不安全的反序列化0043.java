package com.example.mathsim;

import java.io.*;
import java.lang.reflect.Method;
import java.util.Base64;

/**
 * 数学模型仿真管理器
 * 使用反射实现元编程特性
 */
public class SimulationManager {
    // 模拟存储模型状态的序列化数据
    private static final String MODEL_STATE = "rO0ABXNyACRjb20uZXhhbXBsZS5tYXRoLnNpbS5NYXRoTW9kZWwAAAAAAAAAAQIAAUwAA21hdGhUeXBlcQB+AAN4cAAAAHh4";

    /**
     * 动态加载模型类并反序列化状态
     * @param className 客户端传入的模型类名
     * @param encodedState 编码的序列化状态
     * @return 加载的模型实例
     * @throws Exception
     */
    public Object loadModel(String className, String encodedState) throws Exception {
        // 使用反射动态加载类
        Class<?> modelClass = Class.forName(className);
        
        // 危险：直接反序列化用户输入数据
        byte[] data = Base64.getDecoder().decode(encodedState);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 元编程特性：通过反射调用模型初始化方法
            Method initMethod = modelClass.getMethod("init", Object.class);
            return initMethod.invoke(modelClass.newInstance(), ois.readObject());
        }
    }

    /**
     * 保存模型状态到磁盘
     * @param model 模型实例
     * @param filePath 文件路径
     * @throws IOException
     */
    public void saveModel(Object model, String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(model);
        }
    }

    /**
     * 示例数学模型类
     */
    public static class MathModel implements Serializable {
        private String mathType;
        
        public MathModel() {}
        
        public void init(Object config) {
            // 初始化模型配置
            System.out.println("Model initialized with " + config);
        }
        
        // 危险的readObject方法（未正确实现）
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 动态执行数学运算（元编程特性）
            try {
                Class<?> clazz = Class.forName(mathType);
                Method method = clazz.getMethod("calculate", double[].class);
                method.invoke(null, (Object) new double[]{1.0, 2.0});
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SimulationManager manager = new SimulationManager();
        
        // 模拟攻击者输入恶意类名和序列化数据
        String attackerClass = "com.example.mathsim.SimulationManager$MathModel";
        String attackerData = "rO0ABXNyACRjb20uZXhhbXBsZS5tYXRoLnNpbS5NYXRoTW9kZWwAAAAAAAAAAQIAAUwAA21hdGhUeXBlcQB+AAN4cAAAAHh4";
        
        // 触发漏洞
        manager.loadModel(attackerClass, attackerData);
    }
}