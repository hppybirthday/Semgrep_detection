import java.io.*;
import android.util.Log;

public class FileService {
    private static final String TAG = "FileService";
    private String baseDir = "/data/data/com.example.app/files/";

    public String readFile(String fileName) {
        File file = new File(baseDir + fileName);
        StringBuilder content = new StringBuilder();
        try (FileInputStream fis = new FileInputStream(file);
             BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        } catch (IOException e) {
            Log.e(TAG, "Read error: " + e.getMessage());
        }
        return content.toString();
    }

    public void writeFile(String fileName, String data) {
        File file = new File(baseDir + fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data.getBytes());
        } catch (IOException e) {
            Log.e(TAG, "Write error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        FileService service = new FileService();
        if (args.length > 0) {
            String userInput = args[0];
            Log.d(TAG, "Reading file: " + userInput);
            String result = service.readFile(userInput);
            Log.d(TAG, "File content: " + result);
        }
    }
}