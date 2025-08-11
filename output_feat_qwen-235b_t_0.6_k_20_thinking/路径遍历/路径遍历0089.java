import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

interface PluginLoader {
    void loadPlugin(String pluginName) throws IOException;
}

class FileSystemPluginLoader implements PluginLoader {
    private static final String BASE_PATH = "/var/data/analytics/plugins/";
    
    @Override
    public void loadPlugin(String pluginName) throws IOException {
        String pluginPath = BASE_PATH + pluginName;
        File pluginFile = new File(pluginPath);
        
        if (!pluginFile.exists()) {
            throw new IOException("Plugin not found");
        }
        
        // Simulate plugin processing
        processPluginFile(pluginFile);
    }
    
    private void processPluginFile(File file) throws IOException {
        // Vulnerable file operation
        File tempOutput = new File("/tmp/processed_" + file.getName());
        try (FileOutputStream fos = new FileOutputStream(tempOutput)) {
            // Simulated data processing
            fos.write(("Processed content from " + file.getName()).getBytes());
        }
    }
}

class DataProcessingService {
    private PluginLoader pluginLoader;
    
    public DataProcessingService(PluginLoader loader) {
        this.pluginLoader = loader;
    }
    
    public void handleUserRequest(String userInput) {
        try {
            pluginLoader.loadPlugin(userInput);
        } catch (IOException e) {
            System.err.println("Error processing request: " + e.getMessage());
        }
    }
}

public class Application {
    public static void main(String[] args) {
        PluginLoader loader = new FileSystemPluginLoader();
        DataProcessingService service = new DataProcessingService(loader);
        
        // Simulate user input
        if (args.length > 0) {
            System.out.println("Processing request with input: " + args[0]);
            service.handleUserRequest(args[0]);
        } else {
            System.out.println("Usage: java Application <plugin-name>");
        }
    }
}