package com.example.vulnerableapp;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText input = findViewById(R.id.editText);
        Button button = findViewById(R.id.button);
        TextView output = findViewById(R.id.textView);

        button.setOnClickListener(v -> {
            String userInput = input.getText().toString();
            
            try {
                // Vulnerable command construction
                String[] command = {"/system/bin/sh", "-c", "ping -c 1 " + userInput};
                Process process = Runtime.getRuntime().exec(command);
                
                // Capture output streams
                StringBuilder result = new StringBuilder();
                InputStream inputStream = process.getInputStream();
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream)
                );
                
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\
");
                }
                
                // Error stream handling
                InputStream errorStream = process.getErrorStream();
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(errorStream)
                );
                
                while ((line = errorReader.readLine()) != null) {
                    result.append("ERROR: ").append(line).append("\
");
                }
                
                output.setText(result.toString());
                process.waitFor();
                
            } catch (IOException | InterruptedException e) {
                Toast.makeText(this, "Execution error", Toast.LENGTH_SHORT).show();
                Log.e("CommandExec", "Execution failed", e);
            }
        });
    }
}