package com.example.simulation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SimTask {

    @Autowired
    private SimService simService;

    @Scheduled(fixedRate = 60000)
    public void runSimulation() {
        try {
            simService.executeSimulation();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

@Service
public class SimService {

    @Autowired
    private UserService userService;

    @Autowired
    private SimExecutor simExecutor;

    public void executeSimulation() throws IOException, InterruptedException {
        String userInput = userService.getSimulationParameters();
        String processedParam = userService.prepareParameters(userInput);
        simExecutor.runCommand(processedParam);
    }
}

@Service
public class UserService {

    public String getSimulationParameters() {
        return System.getProperty("sim.params", "default_input");
    }

    public String prepareParameters(String input) {
        String sanitized = input.replaceAll("[;]", "");
        return sanitized.replace(" ", "%20");
    }
}

@Service
public class SimExecutor {

    public void runCommand(String param) throws IOException, InterruptedException {
        String command = "run_simulation.exe " + param;
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        int exitCode = process.waitFor();
        System.out.println("Exit code: " + exitCode);
    }
}