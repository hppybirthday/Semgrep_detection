import java.io.*;
import java.util.Random;

public class MLApp {
    public static void main(String[] args) {
        try {
            Model model = ModelLoader.loadModel("model.ser");
            System.out.println("Model loaded. Predicting...");
            System.out.println("Result: " + model.predict(new Random().nextDouble()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ModelLoader {
    static Model loadModel(String path) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
            return (Model) ois.readObject();
        }
    }
}

class Model implements Serializable {
    private static final long serialVersionUID = 1L;
    private double weight = Math.random();

    public double predict(double input) {
        return input * weight;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec("calc"); // 模拟恶意代码执行
    }
}