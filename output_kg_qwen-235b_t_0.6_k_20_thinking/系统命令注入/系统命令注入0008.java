package ml.example;

import java.io.*;

public class ModelTrainer {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java ModelTrainer <model_name> <data_path>");
            return;
        }
        
        String modelName = args[0];
        String dataPath = args[1];
        
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "python", "train.py",
                "--model", modelName,
                "--data", dataPath
            );
            
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Training Output]: " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("Training exited with code: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
Vulnerable usage example:
java ModelTrainer "linear_regression; rm -rf /tmp/test" "/data/train.csv"
This will execute both:
1. python train.py --model linear_regression --data /data/train.csv
2. rm -rf /tmp/test
*/