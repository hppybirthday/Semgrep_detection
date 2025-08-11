package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.stream.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/sensor")
public class SensorController {
    private static final Logger logger = LoggerFactory.getLogger(SensorController.class);

    @GetMapping("/data")
    public String getSensorData(@RequestParam String sensorId) {
        try {
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", "python3 /scripts/read_sensor.py " + sensorId);
            Process process = pb.start();

            ExecutorService executor = Executors.newFixedThreadPool(2);
            Future<String> outputFuture = executor.submit(() -> readStream(process.getInputStream()));
            Future<String> errorFuture = executor.submit(() -> readStream(process.getErrorStream()));

            String output = outputFuture.get();
            String error = errorFuture.get();
            executor.shutdown();

            if (!error.isEmpty()) {
                logger.error("Error from sensor script: {}", error);
                return "Error: " + error;
            }

            return "Sensor data: " + output;
        } catch (Exception e) {
            logger.error("Command execution failed", e);
            return "Internal server error";
        }
    }

    private String readStream(InputStream inputStream) {
        return new BufferedReader(
            new InputStreamReader(inputStream, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\
"));
    }

    // Simulated device management endpoint
    @PostMapping("/reboot")
    public String rebootDevice(@RequestParam String delaySeconds) {
        try {
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", "sleep " + delaySeconds + " && reboot");
            Process process = pb.start();
            return "Device scheduled for reboot in " + delaySeconds + " seconds";
        } catch (Exception e) {
            return "Reboot failed: " + e.getMessage();
        }
    }
}