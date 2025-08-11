import java.io.*;
import java.nio.file.*;
import java.util.function.*;
import java.util.stream.*;

public class ModelProcessor {
    private static final String BASE_PATH = "/safe/models/";

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java ModelProcessor <model-name>");
            return;
        }

        Function<String, File> createModelPath = input -> {
            // 漏洞点：直接拼接路径
            String unsafePath = BASE_PATH + input;
            return new File(unsafePath);
        };

        Consumer<File> processModel = file -> {
            try (Stream<String> lines = Files.lines(file.toPath())) {
                lines.forEach(System.out::println);
                System.out.println("Model processed successfully.");
            } catch (Exception e) {
                System.err.println("Error processing model: " + e.getMessage());
            }
        };

        File modelFile = createModelPath.apply(args[0]);
        processModel.accept(modelFile);
    }
}

/*
编译运行示例：
1. 创建测试文件：echo "ML_MODEL_DATA" > /safe/models/test.mdl
2. 正常使用：java ModelProcessor test.mdl
3. 攻击示例：java ModelProcessor ../../../../etc/passwd
*/