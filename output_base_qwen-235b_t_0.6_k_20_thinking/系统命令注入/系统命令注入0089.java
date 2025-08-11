import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

interface DataProcessor {
    void process(String input) throws IOException;
}

abstract class BaseProcessor implements DataProcessor {
    protected abstract String getScriptName();
}

class ExternalScriptProcessor extends BaseProcessor {
    @Override
    protected String getScriptName() {
        return "data_analytics.py";
    }

    @Override
    public void process(String input) throws IOException {
        String cmd = String.format("python3 %s --file %s", getScriptName(), input);
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Processing result: " + line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DataProcessingService {
    private DataProcessor processor;

    public DataProcessingService(DataProcessor processor) {
        this.processor = processor;
    }

    public void handleUserRequest(String userInput) {
        try {
            processor.process(userInput);
        } catch (IOException e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }
}

public class DataAnalyticsPlatform {
    public static void main(String[] args) {
        DataProcessor processor = new ExternalScriptProcessor();
        DataProcessingService service = new DataProcessingService(processor);
        
        if (args.length == 0) {
            System.out.println("Usage: java DataAnalyticsPlatform <filename>");
            return;
        }
        
        String userInput = args[0];
        System.out.println("Starting analytics processing for: " + userInput);
        service.handleUserRequest(userInput);
    }
}