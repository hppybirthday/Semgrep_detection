package com.example.vulnerableapp;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileOperationsActivity extends AppCompatActivity {
    private EditText fileNameInput;
    private TextView resultView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_operations);

        fileNameInput = findViewById(R.id.fileNameInput);
        resultView = findViewById(R.id.resultView);
        Button executeBtn = findViewById(R.id.executeBtn);

        executeBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String userInput = fileNameInput.getText().toString();
                if (userInput.isEmpty()) {
                    Toast.makeText(FileOperationsActivity.this, 
                        "Please enter a file name", Toast.LENGTH_SHORT).show();
                    return;
                }

                try {
                    // Vulnerable command execution
                    Process process = Runtime.getRuntime().exec(
                        "sh -c \\"zip -r /sdcard/backup/" + userInput + " /sdcard/files/" + userInput + "\\"");
                    
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    
                    int exitCode = process.waitFor();
                    resultView.setText("Exit code: " + exitCode + "\
Output:\
" + output.toString());
                    
                } catch (IOException | InterruptedException e) {
                    resultView.setText("Error: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        });
    }
}