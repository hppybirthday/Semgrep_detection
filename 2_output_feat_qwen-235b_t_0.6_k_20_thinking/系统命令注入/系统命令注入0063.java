package com.enterprise.scheduler.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.concurrent.*;
import java.util.logging.*;

@RestController
public class SystemCommandController {
    private static final Logger logger = Logger.getLogger(SystemCommandController.class.getName());

    @GetMapping("/exec")
    public String executeCommand(@RequestParam String cmd) {
        try {
            CommandTask task = new CommandTask(cmd);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<String> result = executor.submit(task);
            executor.shutdown();
            return "Result: " + result.get();
        } catch (Exception e) {
            logger.severe("Execution error: " + e.getMessage());
            return "Command failed";
        }
    }

    static class CommandTask implements Callable<String> {
        private final String command;

        CommandTask(String cmd) {
            this.command = cmd;
        }

        @Override
        public String call() throws Exception {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo \\"Starting trace\\" && traceroute " + command);
            Process process = pb.start();
            return new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines().reduce((a, b) -> a + "\
" + b).orElse("");
        }
    }
}