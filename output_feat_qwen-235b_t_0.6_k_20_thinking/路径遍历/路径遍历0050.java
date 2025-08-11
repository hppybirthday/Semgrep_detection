import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.aspectj.EnableSpringConfigured;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@EnableSpringConfigured
@RestController
@RequestMapping("/chat")
public class ChatApplication implements CommandLineRunner {
    private static final String BASE_PATH = System.getenv("CHAT_LOG_DIR");

    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }

    @GetMapping("/download/{user}")
    public String downloadLog(@PathVariable String user) throws IOException {
        FileService fileService = new FileService();
        return fileService.readLogFile(user);
    }

    @Aspect
    @Component
    public class FileOperationAspect {
        @Around("execution(* FileService.deleteLogFile(..))")
        public Object logDeleteOperation(ProceedingJoinPoint joinPoint) throws Throwable {
            Object[] args = joinPoint.getArgs();
            String user = (String) args[0];
            System.out.println("Deleting log for user: " + user);
            Object result = joinPoint.proceed();
            System.out.println("Log deletion completed: " + user);
            return result;
        }
    }

    class FileService {
        public String readLogFile(String user) throws IOException {
            Path filePath = Paths.get(String.format("%s/%s/debug.log", BASE_PATH, user));
            if (!Files.exists(filePath)) {
                throw new IOException("File not found");
            }
            return Files.readString(filePath);
        }

        public void deleteLogFile(String user) throws IOException {
            Path filePath = Paths.get(String.format("%s/%s/debug.log", BASE_PATH, user));
            Files.delete(filePath);
        }
    }
}