import java.io.*;
import java.util.*;
import spark.*;

public class ModelEvaluator {
    public static void main(String[] args) {
        Spark.post("/evaluate", (req, res) -> {
            String modelName = req.queryParams("model");
            String datasetPath = req.queryParams("dataset");
            
            // 模拟机器学习模型评估流程
            String pythonScriptPath = "/opt/ml_scripts/evaluate_model.py";
            String outputDir = "/var/output/results_" + System.currentTimeMillis();
            
            // 创建输出目录
            new File(outputDir).mkdirs();
            
            // 构造执行命令（存在漏洞的关键点）
            String command = "python3 " + pythonScriptPath + 
                           " --model=" + modelName + 
                           " --dataset=" + datasetPath + 
                           " > " + outputDir + "/output.log 2>&1";
            
            // 执行系统命令
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            int exitCode = process.waitFor();
            res.type("application/json");
            return String.format("{\\"status\\":\\"%s\\", \\"output_dir\\":\\"%s\\"}", 
                exitCode == 0 ? "success" : "failed", outputDir);
        });
    }
}

/*
// 漏洞利用示例：
curl -X POST "http://localhost:4567/evaluate?model=denseNet&dataset=/data/valid;rm -rf /var/output/*"

// 可能导致执行的恶意命令：
python3 /opt/ml_scripts/evaluate_model.py --model=denseNet --dataset=/data/valid;rm -rf /var/output/* > /var/output/results_1700000000/output.log 2>&1
*/