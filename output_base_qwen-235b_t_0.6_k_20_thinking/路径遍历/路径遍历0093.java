import java.io.*;
import java.util.Scanner;

// 模型数据类
class ModelData {
    private String content;

    public ModelData(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

// 模型文件管理类
class ModelFileManager {
    private String baseDirectory;

    public ModelFileManager(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    // 存在漏洞的文件读取方法
    public ModelData loadModel(String filename) throws IOException {
        File file = new File(baseDirectory + "/" + filename);
        if (!file.exists()) {
            throw new FileNotFoundException("Model file not found");
        }
        
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return new ModelData(content.toString());
    }

    // 存在漏洞的文件保存方法
    public void saveModel(String filename, String content) throws IOException {
        File file = new File(baseDirectory + "/" + filename);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
        }
    }
}

// 仿真控制器类
class SimulationController {
    private ModelFileManager fileManager;

    public SimulationController(String baseDirectory) {
        this.fileManager = new ModelFileManager(baseDirectory);
    }

    public void handleUserRequest(String action, String filename, String content) {
        try {
            switch (action) {
                case "load":
                    System.out.println("Loaded model content:");
                    System.out.println(fileManager.loadModel(filename).getContent());
                    break;
                case "save":
                    fileManager.saveModel(filename, content);
                    System.out.println("Model saved successfully");
                    break;
                default:
                    System.out.println("Invalid action");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

// 测试类
public class VulnerableSimulation {
    public static void main(String[] args) {
        // 模拟基础目录
        String baseDirectory = "models/simulations";
        new File(baseDirectory).mkdirs();
        
        SimulationController controller = new SimulationController(baseDirectory);
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Math Simulation System");
        System.out.print("Enter action (load/save): ");
        String action = scanner.nextLine();
        
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine();
        
        if (action.equals("save")) {
            System.out.print("Enter content to save: ");
            String content = scanner.nextLine();
            controller.handleUserRequest(action, filename, content);
        } else {
            controller.handleUserRequest(action, filename, "");
        }
    }
}