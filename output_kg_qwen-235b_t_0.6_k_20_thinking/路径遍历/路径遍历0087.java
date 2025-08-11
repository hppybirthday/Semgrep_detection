import java.io.*;
import java.nio.file.*;

public class ModelTrainer {
    private static final String BASE_DIR = "/var/ml_data/";

    public void trainModel(String datasetName) {
        try {
            Path filePath = Paths.get(BASE_DIR + datasetName);
            byte[] data = Files.readAllBytes(filePath);
            System.out.println("Training model with dataset size: " + data.length);
        } catch (Exception e) {
            System.err.println("Training failed: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        ModelTrainer trainer = new ModelTrainer();
        if (args.length > 0) {
            // Simulating user input from command line
            // Vulnerable to path traversal
            trainer.trainModel(args[0]);
        } else {
            System.out.println("Usage: java ModelTrainer <dataset_name>");
        }
    }
}

// Vulnerable usage example:
// java ModelTrainer "../../../../etc/passwd"
// java ModelTrainer "../../../../../tmp/evil_model.bin"

// Normal usage:
// java ModelTrainer "training_data.csv"