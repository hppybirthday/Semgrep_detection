import java.io.*;
import java.lang.reflect.Method;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class TaskController {
    @GetMapping("/schedule")
    public String scheduleTask(@RequestParam String job) {
        try {
            String cmd = "sh -c \\"echo Scheduling job: " + job + "; /usr/local/bin/task-handler " + job + "\\"";
            Process process = Runtime.getRuntime().exec(cmd, null, new File("/var/tasks"));
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            return output.toString();
            
        } catch (Exception e) {
            return "Execution failed: " + e.getMessage();
        }
    }

    // 元编程动态执行示例
    private Object dynamicExecute(String className, String methodName, Object... args) {
        try {
            Class<?> cls = Class.forName(className);
            Method method = cls.getMethod(methodName, Arrays.stream(args)
                .map(Object::getClass)
                .toArray(Class[]::new));
            return method.invoke(null, args);
        } catch (Exception e) {
            return null;
        }
    }
}