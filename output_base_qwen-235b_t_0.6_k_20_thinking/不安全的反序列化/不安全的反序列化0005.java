import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.Method;
import java.util.Base64;

@SpringBootApplication
@RestController
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

    @PostMapping(path = "/vulnerable-endpoint", consumes = MediaType.APPLICATION_JSON_VALUE)
    public String processSerializedData(@RequestBody byte[] payload) {
        try {
            // 模拟企业级反序列化场景
            ByteArrayInputStream bais = new ByteArrayInputStream(payload);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            
            // 元编程风格：反射调用对象方法
            Method method = obj.getClass().getMethod("execute");
            String result = (String) method.invoke(obj);
            return "Execution result: " + result;
            
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }
}

// 模拟业务场景中的可执行接口
class CommandTask implements java.io.Serializable {
    private String command;
    
    public CommandTask(String cmd) {
        this.command = cmd;
    }
    
    public String execute() {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            java.io.InputStream is = pb.start().getInputStream();
            byte[] buffer = new byte[1024];
            int len = is.read(buffer);
            return new String(buffer, 0, len);
        } catch (IOException e) {
            return "Execution failed: " + e.getMessage();
        }
    }
}