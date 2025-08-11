package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Arrays;

@RestController
public class FileController {
    @GetMapping("/files")
    public String listFiles(@RequestParam String filename) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ls -l " + filename);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @GetMapping("/backup")
    public String backupFiles(@RequestParam String src, @RequestParam String dest) {
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/cp", "-r", src, dest});
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}