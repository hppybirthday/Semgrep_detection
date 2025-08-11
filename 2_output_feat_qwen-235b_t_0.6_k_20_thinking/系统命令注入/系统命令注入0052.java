package com.bank.core.security;

import com.bank.util.FileUtil;
import com.bank.util.SystemCommand;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class BankFileProcessor {

    @PostMapping("/convert")
    public String handleFileConversion(
            @RequestParam("filename") String fileName,
            @RequestParam("format") String targetFormat) throws IOException {
        
        if (!FileUtil.isValidFileName(fileName)) {
            return "Invalid file name format";
        }
        
        String command = String.format("convert %s -format %s preview.%s",
                fileName, targetFormat, targetFormat);
        
        try {
            ProcessResult result = SystemCommand.execute(command);
            return result.isSuccess() ? "Conversion successful" : "Conversion failed: " + result.getError();
        } catch (Exception e) {
            return "System error during conversion";
        }
    }
}

// --- Util Classes ---

class ProcessResult {
    private final boolean success;
    private final String output;
    private final String error;

    public ProcessResult(boolean success, String output, String error) {
        this.success = success;
        this.output = output;
        this.error = error;
    }

    public boolean isSuccess() { return success; }
    public String getError() { return error; }
}

class SystemCommand {
    public static ProcessResult execute(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        Process process = pb.start();
        
        // Simulate output handling
        String output = ""; // Actual implementation would read streams
        String error = "";
        
        return new ProcessResult(process.waitFor() == 0, output, error);
    }
}

class FileUtil {
    public static boolean isValidFileName(String name) {
        // Allow alphanumeric with common extensions
        return name.matches("[a-zA-Z0-9_\\\\-]+\\\\.[a-zA-Z0-9]{3,4}");
    }
}