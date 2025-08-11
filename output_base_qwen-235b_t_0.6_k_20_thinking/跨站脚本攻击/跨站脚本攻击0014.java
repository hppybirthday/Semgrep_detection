package com.example.xssdemo;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.Html;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText usernameInput = findViewById(R.id.username);
        Button submitBtn = findViewById(R.id.submit);

        submitBtn.setOnClickListener(v -> {
            String username = usernameInput.getText().toString();
            Intent intent = new Intent(MainActivity.this, ProfileActivity.class);
            intent.putExtra("username", username);
            startActivity(intent);
        });
    }
}

// ProfileActivity.java
package com.example.xssdemo;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.widget.TextView;

public class ProfileActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_profile);

        String username = getIntent().getStringExtra("username", "Guest");
        TextView welcomeText = findViewById(R.id.welcome);
        WebView bioView = findViewById(R.id.bio_webview);

        // 模拟从服务器获取的富文本内容
        String serverResponse = "<div>Welcome back, " + username + "!</div>" + 
                              "<script>alert('XSS漏洞触发！');</script>";

        // 危险操作：直接加载原始HTML
        bioView.loadDataWithBaseURL(null, serverResponse, "text/html", "UTF-8", null);
        
        // 错误示范：认为HTML.fromHtml能防御XSS
        welcomeText.setText(Html.fromHtml(
            "<b>最新动态：</b>欢迎用户：" + username
        ));
    }
}