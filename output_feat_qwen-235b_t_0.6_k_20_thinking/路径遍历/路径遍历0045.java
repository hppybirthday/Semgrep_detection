import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.model.PutObjectRequest;

public class ModelService {
    private static final String BASE_DIR = "/var/models/";
    private OSSClient ossClient;

    public ModelService(OSSClient ossClient) {
        this.ossClient = ossClient;
    }

    public void exportModel(String modelId, String outputDir) throws IOException {
        File baseDirectory = new File(BASE_DIR);
        File targetDir = new File(baseDirectory, outputDir);
        
        // 模拟生成模型文件
        File modelFile = new File(targetDir, modelId + ".mod");
        
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        
        try (FileWriter writer = new FileWriter(modelFile)) {
            writer.write(generateModelContent(modelId));
        }
        
        // 上传到OSS
        String bucketName = "model-storage";
        String objectKey = "models/" + modelId + ".mod";
        ossClient.putObject(new PutObjectRequest(bucketName, objectKey, modelFile));
    }

    private String generateModelContent(String modelId) {
        // 模拟生成数学模型内容
        return String.format("ModelID: %s\
Equations: [dx/dt = -kx]\
Parameters: {k=0.5}", modelId);
    }

    public static void main(String[] args) {
        // 模拟服务调用
        OSSClient ossClient = new OSSClient("endpoint", "accessKeyId", "accessKeySecret");
        ModelService service = new ModelService(ossClient);
        
        try {
            // 恶意输入示例
            String maliciousDir = "../../etc/passwd";
            service.exportModel("malicious_model", maliciousDir);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}