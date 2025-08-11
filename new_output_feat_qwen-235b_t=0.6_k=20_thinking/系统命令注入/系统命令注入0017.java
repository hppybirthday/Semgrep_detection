package com.example.crawler.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

@Service
public class FileProcessor {
    private static final String BASE_DIR = "/var/uploads/";
    private final FileValidationService validator;

    public FileProcessor(FileValidationService validator) {
        this.validator = validator;
    }

    @Scheduled(cron = "0 0/5 * * * ?")
    public void processUploadedFiles() {
        try {
            List<String> files = Files.readAllLines(Paths.get(BASE_DIR + "queue.txt"));
            for (String filename : files) {
                if (validator.validateFile(filename)) {
                    executeProcessingCommand(filename);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void executeProcessingCommand(String filename) {
        try {
            String command = buildCommand(filename);
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String buildCommand(String filename) {
        return "magic-pdf process " + BASE_DIR + filename;
    }
}

class FileValidationService {
    boolean validateFile(String filename) {
        File file = new File(FileProcessor.BASE_DIR + filename);
        return file.exists() && file.isFile() && filename.endsWith(".pdf");
    }
}

// 模拟的magic-pdf命令处理类
@Service
class PdfProcessor {
    void process(String[] args) {
        if (args.length < 2 || !args[0].equals("process")) return;
        try {
            String content = FileUtils.readFileToString(new File(args[1]), "UTF-8");
            // 实际处理逻辑...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}