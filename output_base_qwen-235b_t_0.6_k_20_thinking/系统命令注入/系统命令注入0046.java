import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class FileCompressor {

    public static void main(String[] args) {
        SpringApplication.run(FileCompressor.class, args);
    }

    @RestController
    class CompressionController {

        @GetMapping("/compress")
        public String compressFile(@RequestParam String filename) {
            try {
                // 模拟快速原型开发中的不安全实现
                Process process = Runtime.getRuntime().exec(
                    "zip -r /storage/emulated/0/compressed/" + filename + " /storage/emulated/0/files/" + filename);
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                return "压缩结果:\
" + output.toString();
            } catch (IOException e) {
                return "压缩失败: " + e.getMessage();
            }
        }
    }
}

/*
AndroidManifest.xml 需要包含:
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
*/