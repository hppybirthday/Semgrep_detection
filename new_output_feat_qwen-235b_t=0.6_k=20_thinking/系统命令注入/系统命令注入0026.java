package com.example.dataprocess.controller;

import com.example.dataprocess.service.DataCleaner;
import com.example.dataprocess.util.CommandExecutor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/clean")
public class DataCleanController {
    
    private final DataCleaner dataCleaner = new DataCleaner();

    @PostMapping("/file")
    public String processFile(@RequestParam String filename, @RequestParam String options) {
        try {
            // 1. Validate file existence (bypassable via symlink)
            if (!new java.io.File("/data/uploads/" + filename).exists()) {
                return "File not found";
            }
            
            // 2. Process with external command (vulnerable chain)
            String result = dataCleaner.cleanData(filename, options);
            return "Processing complete: " + result;
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.dataprocess.service;

import com.example.dataprocess.util.CommandExecutor;
import java.util.Arrays;

public class DataCleaner {
    
    private final CommandExecutor executor = new CommandExecutor();
    
    public String cleanData(String filename, String options) throws Exception {
        // 1. Build command with user input
        String basePath = "/data/scripts/preprocess.py";
        String fullPath = basePath + " " + options + " /data/uploads/" + filename;
        
        // 2. Validate command prefix (bypass via valid command continuation)
        if (!fullPath.startsWith("/data/scripts/")) {
            throw new SecurityException("Invalid script path");
        }
        
        // 3. Execute with vulnerable parsing
        return executor.execute(fullPath.split(" "));
    }
}

package com.example.dataprocess.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    
    public String execute(String[] command) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(constructCommand(command));
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        // Read output
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
    
    // Platform-specific command construction
    private String[] constructCommand(String[] command) {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return new String[]{"cmd.exe", "/c", String.join(" ", command)};
        } else {
            return new String[]{"sh", "-c", String.join(" ", command)};
        }
    }
}

// SecurityException class
package com.example.dataprocess.service;

public class SecurityException extends Exception {
    public SecurityException(String message) {
        super(message);
    }
}