import java.io.*;
import java.nio.file.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class ModelController {
    @PostMapping("/train")
    public String processData(@RequestParam String prefix, @RequestParam String suffix) {
        try {
            File result = FileService.mergeFiles(prefix, suffix);
            return "Model saved at " + result.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public static void main(String[] args) throws IOException {
        new ModelController().processData("normal","file.csv");
    }
}

class FileService {
    static File mergeFiles(String prefix, String suffix) throws IOException {
        return GenerateUtil.generateFile(prefix, suffix);
    }
}

class GenerateUtil {
    static File generateFile(String prefix, String suffix) throws IOException {
        String basePath = "/var/ml_data/";
        String unsafePath = basePath + prefix + suffix;
        File target = new File(unsafePath);
        
        // 模拟模型训练结果写入
        Files.write(target.toPath(), "ML_MODEL_DATA".getBytes());
        return target;
    }
}