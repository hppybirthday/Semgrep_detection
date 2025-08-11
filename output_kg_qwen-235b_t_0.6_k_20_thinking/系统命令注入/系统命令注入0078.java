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

public class CommandInjectionActivity extends Activity {
    EditText inputFilename;
    TextView outputText;
    Button executeBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputFilename = findViewById(R.id.input_filename);
        outputText = findViewById(R.id.output_text);
        executeBtn = findViewById(R.id.execute_btn);

        executeBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String filename = inputFilename.getText().toString();
                    Process process = Runtime.getRuntime().exec("cat " + filename);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    outputText.setText(output.toString());
                } catch (IOException e) {
                    outputText.setText("Error: " + e.getMessage());
                }
            }
        });
    }
}

/*
AndroidManifest.xml:
<uses-permission android:name="android.permission.INTERNET"/>
<application
    android:allowBackup="true"
    android:label="@string/app_name">
    <activity android:name=".CommandInjectionActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
*/