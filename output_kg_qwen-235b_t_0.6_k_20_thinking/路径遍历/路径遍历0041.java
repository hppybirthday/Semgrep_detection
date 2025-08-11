import java.io.*;
import java.nio.file.*;
import java.util.stream.*;

@FunctionalInterface
interface DataCleaner {
    Stream<String> clean(Stream<String> data);
}

public class VulnerableDataProcessor {
    private static final String BASE_DIR = "/var/data/uploads";
    private static final String OUTPUT_DIR = "/var/data/cleaned";

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java VulnerableDataProcessor <inputFile> <outputDir>");
            return;
        }
        
        String userInputFile = args[0];
        String userOutputDir = args[1];
        
        try {
            processData(userInputFile, userOutputDir);
        } catch (Exception e) {
            System.err.println("Error processing data: " + e.getMessage());
        }
    }

    public static void processData(String inputFileName, String outputDir) throws IOException {
        Path inputPath = Paths.get(BASE_DIR, inputFileName);
        Path outputPath = Paths.get(OUTPUT_DIR, outputDir);
        
        // 创建输出目录（存在漏洞）
        Files.createDirectories(outputPath);
        
        // 使用函数式编程处理数据
        DataCleaner cleaner = dataStream -> dataStream
            .map(line -> line.replaceAll("\\s+", " "))
            .filter(line -> !line.isEmpty())
            .map(String::trim);

        try (BufferedReader reader = Files.newBufferedReader(inputPath);
             BufferedWriter writer = Files.newBufferedWriter(outputPath.resolve("cleaned_data.txt"))) {
            
            Stream<String> dataStream = reader.lines();
            Stream<String> cleanedStream = cleaner.clean(dataStream);
            
            cleanedStream.forEach(line -> {
                try {
                    writer.write(line);
                    writer.newLine();
                } catch (IOException e) {
                    throw new RuntimeException("Write error: " + e.getMessage());
                }
            });
            
        } catch (IOException e) {
            handleIOException(e, inputPath.toString());
        }
    }

    private static void handleIOException(Exception e, String path) {
        System.err.println("Failed to process file: " + path);
        System.err.println("Error details: " + e.getClass().getName() + ": " + e.getMessage());
        
        // 漏洞点：直接暴露文件路径信息
        if (e.getMessage().contains("No such file or directory")) {
            System.out.println("File not found in expected location. Possible path traversal attempt?");
        }
    }
}