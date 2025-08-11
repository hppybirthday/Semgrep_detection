package com.example.vulnerableapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainActivity extends Activity {
    private EditText hostInput;
    private TextView resultText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        hostInput = findViewById(R.id.host_input);
        resultText = findViewById(R.id.result_text);
        Button pingButton = findViewById(R.id.ping_button);

        pingButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String host = hostInput.getText().toString();
                if (host.isEmpty()) return;

                try {
                    // Vulnerable command construction
                    ProcessBuilder processBuilder = new ProcessBuilder("ping", "-c", "1", host);
                    Process process = processBuilder.start();

                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                    );
                    StringBuilder output = new StringBuilder();
                    String line;

                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }

                    int exitCode = process.waitFor();
                    resultText.setText("Exit code: " + exitCode + "\
Output:\
" + output.toString());

                } catch (IOException | InterruptedException e) {
                    resultText.setText("Error: " + e.getMessage());
                }
            }
        });
    }
}