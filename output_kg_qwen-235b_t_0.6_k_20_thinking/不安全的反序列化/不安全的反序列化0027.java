package com.mathsim.model;

import java.io.*;
import java.util.*;

/**
 * 数学模型抽象基类
 * 支持参数序列化与反序列化
 */
public abstract class MathModel implements Serializable {
    protected Map<String, Object> parameters;
    protected String modelName;

    public MathModel(String name) {
        this.modelName = name;
        this.parameters = new HashMap<>();
    }

    public abstract double calculate(double[] inputs);

    public void saveModel(String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(filePath))) {
            oos.writeObject(this);
        }
    }

    public static MathModel loadModel(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filePath))) {
            // 存在漏洞的反序列化操作
            return (MathModel) ois.readObject();
        }
    }

    public void setParameter(String key, Object value) {
        parameters.put(key, value);
    }

    public Object getParameter(String key) {
        return parameters.get(key);
    }
}

/**
 * 线性回归模型实现
 */
class LinearRegressionModel extends MathModel {
    private double[] coefficients;

    public LinearRegressionModel() {
        super("LinearRegression");
    }

    @Override
    public double calculate(double[] inputs) {
        if (coefficients == null || coefficients.length != inputs.length + 1) {
            throw new IllegalArgumentException("Invalid coefficients or input dimensions");
        }
        double result = coefficients[0];
        for (int i = 0; i < inputs.length; i++) {
            result += coefficients[i + 1] * inputs[i];
        }
        return result;
    }
}

/**
 * 模型服务类
 */
public class ModelService {
    private Map<String, MathModel> modelCache = new HashMap<>();

    public void registerModel(String name, MathModel model) {
        modelCache.put(name, model);
    }

    public double executeModel(String modelName, double[] inputs) {
        MathModel model = modelCache.get(modelName);
        if (model == null) {
            throw new IllegalArgumentException("Model not found: " + modelName);
        }
        return model.calculate(inputs);
    }

    public static void main(String[] args) {
        try {
            // 创建并保存模型
            LinearRegressionModel model = new LinearRegressionModel();
            model.setParameter("description", "Test model for simulation");
            model.saveModel("model.data");

            // 漏洞触发点：加载不可信模型
            MathModel loadedModel = MathModel.loadModel("model.data");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}