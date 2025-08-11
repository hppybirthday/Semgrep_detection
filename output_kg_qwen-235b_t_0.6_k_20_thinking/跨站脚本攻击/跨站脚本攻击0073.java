package com.example.xss;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends Activity {
    EditText input;
    Button submit;
    WebView output;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        input = findViewById(R.id.input);
        submit = findViewById(R.id.submit);
        output = findViewById(R.id.output);

        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String userInput = input.getText().toString();
                // 漏洞点：直接将用户输入作为HTML加载
                output.loadData(userInput, "text/html", "UTF-8");
            }
        });
    }
}