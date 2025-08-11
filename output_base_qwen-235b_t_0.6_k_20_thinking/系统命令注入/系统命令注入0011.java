package com.bank.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Controller
@RequestMapping("/api/transactions")
public class TransactionController {
    
    @GetMapping("/execute")
    @ResponseBody
    public String executeTransaction(@RequestParam String accountId) {
        StringBuilder output = new StringBuilder();
        try {
            // Vulnerable command execution
            String cmd = "sh -c \\"process_transaction.sh " + accountId + "\\"";
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                output.append("Error executing transaction: ").append(exitCode);
            }
            
        } catch (IOException | InterruptedException e) {
            output.append("Execution failed: ").append(e.getMessage());
        }
        return output.toString();
    }
    
    @GetMapping("/log")
    @ResponseBody
    public String getTransactionLog(@RequestParam String logId) {
        // Another vulnerable endpoint
        String cmd = "cat /var/log/bank/transactions/" + logId + ".log";
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            System.err.println("Log retrieval failed: " + e.getMessage());
        }
        return "Logged";
    }
}