package com.crm.export;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.function.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/export")
@FunctionalInterface
public interface DataExportHandler {
    
    static String executeCommand(String cmd) {
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String result = reader.lines().collect(Collectors.joining("\
"));
            process.waitFor();
            return result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @GetMapping("/contacts")
    default Supplier<String> exportContacts() {
        return () -> "Export functionality placeholder";
    }

    @GetMapping("/reports")
    default Function<String, String> generateReport() {
        return (format) -> "Report generated in " + format;
    }

    @GetMapping("/archive")
    default BiFunction<String, String, String> createArchive() {
        return (fileName, type) -> {
            String archiveName = System.getProperty("user.dir") + "/exports/" + fileName;
            String command = "zip -r " + archiveName + " " + 
                System.getProperty("user.dir") + "/data/contacts." + type;
            return executeCommand(command);
        };
    }

    @GetMapping("/download")
    default Predicate<String> validateDownload() {
        return (fileName) -> fileName != null && !fileName.isEmpty();
    }

    // 漏洞触发点：命令拼接
    @GetMapping("/download/zip")
    default Consumer<String> downloadZip() {
        return (fileName) -> {
            try {
                // 危险的命令构造方式
                String command = "zip -r " + System.getProperty("user.dir") + "/downloads/" + 
                               fileName + " " + System.getProperty("user.dir") + "/exports/*";
                Runtime.getRuntime().exec(command);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }

    // 漏洞验证接口
    @GetMapping("/exploit")
    default TriFunction<String, String, String, String> testVuln() {
        return (base, op, payload) -> {
            try {
                // 构造恶意命令
                String command = "zip -r " + base + " " + 
                               System.getProperty("user.dir") + "/data/" + 
                               (op.isEmpty() ? "" : "; " + op + " " + payload);
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                return reader.lines().collect(Collectors.joining("\
"));
            } catch (Exception e) {
                return "Exploit failed: " + e.getMessage();
            }
        };
    }

    // 辅助函数式接口定义
    @FunctionalInterface
    interface TriFunction<T, U, V, R> {
        R apply(T t, U u, V v);
    }
}