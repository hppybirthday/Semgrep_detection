import java.io.File;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.apache.commons.io.FileUtils;

public class MLModelHandler {
    private static final String BASE_DIR = "/var/ml_models/";
    private static final String MODEL_EXT = ".model";

    // 函数式接口处理模型保存
    public static Consumer<String> saveModel = (String outputDir) -> {
        try {
            // 路径拼接漏洞点
            String targetPath = Paths.get(BASE_DIR, outputDir).toString();
            File modelFile = new File(targetPath + MODEL_EXT);

            // 模拟模型文件创建
            if (modelFile.createNewFile()) {
                System.out.println("Model saved at: " + modelFile.getAbsolutePath());
            }

            // 危险的文件清理逻辑
            Optional.of(modelFile)
                   .filter(File::exists)
                   .ifPresent(FileUtils::deleteQuietly);

        } catch (Exception e) {
            System.err.println("Model operation failed: " + e.getMessage());
        }
    };

    // 模型训练流水线
    public static void trainModel(String datasetPath, String outputDir) {
        Stream.of(datasetPath)
              .map(path -> new File(path).getName().replace(".data", ""))
              .forEach(modelName -> {
                  System.out.println("Training model: " + modelName);
                  saveModel.accept(outputDir + File.separator + modelName);
              });
    }

    public static void main(String[] args) {
        // 模拟攻击参数
        String userInput = "../../etc/passwd"; // 恶意输入
        String dataset = "/data/training_sets/user_input.data";

        // 触发漏洞
        trainModel(dataset, userInput);
    }
}