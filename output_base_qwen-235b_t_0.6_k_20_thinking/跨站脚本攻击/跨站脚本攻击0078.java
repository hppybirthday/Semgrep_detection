package com.example.xss;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends Activity {
    EditText input;
    Button submit;
    WebView display;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        input = findViewById(R.id.input);
        submit = findViewById(R.id.submit);
        display = findViewById(R.id.display);

        display.getSettings().setJavaScriptEnabled(true);

        submit.setOnClickListener(v -> {
            String userInput = input.getText().toString();
            String html = "<html><body><h1>User Input:</h1><p>" + userInput + "</p></body></html>";
            display.loadData(html, "text/html", "UTF-8");
        });
    }
}