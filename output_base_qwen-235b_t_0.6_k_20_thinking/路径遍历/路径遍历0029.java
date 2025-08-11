import java.io.*;
import java.nio.file.*;
import java.util.*;

interface SimulationModel {
    void initialize(String configPath);
    void runSimulation();
}

abstract class AbstractModel implements SimulationModel {
    protected Map<String, String> parameters = new HashMap<>();
    protected ConfigLoader configLoader;

    public AbstractModel() {
        this.configLoader = new ConfigLoader();
    }
}

class LinearModel extends AbstractModel {
    @Override
    public void initialize(String configPath) {
        parameters = configLoader.loadConfig(configPath);
    }

    @Override
    public void runSimulation() {
        System.out.println("Running linear simulation with parameters: " + parameters);
    }
}

class ConfigLoader {
    private final String baseDirectory = "/var/sim_data/";

    public Map<String, String> loadConfig(String fileName) {
        Map<String, String> config = new HashMap<>();
        try {
            Path filePath = Paths.get(baseDirectory + fileName);
            List<String> lines = Files.readAllLines(filePath);
            
            for (String line : lines) {
                String[] parts = line.split("=");
                if (parts.length == 2) {
                    config.put(parts[0].trim(), parts[1].trim());
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading config: " + e.getMessage());
        }
        return config;
    }
}

public class ModelingFramework {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java ModelingFramework <model_type> <config_file>");
            return;
        }

        String modelType = args[0];
        String configPath = args[1];

        SimulationModel model;
        
        switch (modelType) {
            case "linear":
                model = new LinearModel();
                break;
            default:
                System.out.println("Unsupported model type");
                return;
        }

        model.initialize(configPath);
        model.runSimulation();
    }
}