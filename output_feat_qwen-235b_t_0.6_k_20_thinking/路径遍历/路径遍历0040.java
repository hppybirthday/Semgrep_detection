import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class ModelStorage {
    private static final String BASE_PATH = "/var/ml/models/";
    private static final String SEPARATOR = File.separator;

    public void storeModel(String modelName, byte[] modelData) throws IOException {
        String filePath = BASE_PATH + SEPARATOR + modelName;
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(modelData);
        }
    }

    public byte[] retrieveModel(String modelName) throws IOException {
        String filePath = BASE_PATH + SEPARATOR + modelName;
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("Model not found");
        }
        
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(data);
        }
        return data;
    }

    public void deleteModel(String modelName) throws IOException {
        String filePath = BASE_PATH + SEPARATOR + modelName;
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
    }

    public static void main(String[] args) {
        ModelStorage storage = new ModelStorage();
        try {
            // 模拟存储模型
            storage.storeModel("v1.0/model.pkl", "fake_model_data".getBytes());
            
            // 模拟删除请求（存在漏洞的调用）
            if (args.length > 0) {
                System.out.println("Attempting to delete: " + args[0]);
                storage.deleteModel(args[0]);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}