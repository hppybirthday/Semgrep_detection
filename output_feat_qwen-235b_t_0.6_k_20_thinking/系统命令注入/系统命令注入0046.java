package com.example.vulnerableapp;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class CommandExecutionService extends Service {
    private static final String TAG = "CommandExecution";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String action = intent.getAction();
            if (action != null && action.equals("EXECUTE_SCRIPT")) {
                String hostname = intent.getStringExtra("hostname");
                executePingCommand(hostname);
            }
        }
        return START_NOT_STICKY;
    }

    private void executePingCommand(String hostname) {
        try {
            List<String> commands = new ArrayList<>();
            commands.add("ping");
            commands.add("-c");
            commands.add("4");
            commands.add(hostname); // Vulnerable point: Unsanitized user input

            ProcessBuilder processBuilder = new ProcessBuilder(commands);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }

            int exitCode = process.waitFor();
            Log.d(TAG, "Command output: " + output.toString());
            Log.d(TAG, "Exit code: " + exitCode);

        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Command execution failed", e);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}