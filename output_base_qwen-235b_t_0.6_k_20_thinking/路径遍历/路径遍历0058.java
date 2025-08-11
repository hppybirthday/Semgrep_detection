import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class DataCleaner {
    @GetMapping("/clean")
    public String cleanData(String fileName) throws Exception {
        Path path = Paths.get("src/main/resources/data/" + fileName);
        if(!Files.exists(path)) return "File not found";
        
        StringBuilder cleaned = new StringBuilder();
        Files.readAllLines(path).forEach(line -> {
            cleaned.append(line.replaceAll("[^a-zA-Z0-9]", ""));
            cleaned.append(System.lineSeparator());
        });
        
        Files.write(path, cleaned.toString().getBytes());
        return "Data cleaned successfully";
    }

    public static void main(String[] args) {
        SpringApplication.run(DataCleaner.class, args);
    }
}