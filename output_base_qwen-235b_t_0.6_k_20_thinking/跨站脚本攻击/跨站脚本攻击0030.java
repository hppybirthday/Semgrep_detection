package com.example.xssdemo;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;

public class ChatActivity extends Activity {
    private EditText messageInput;
    private WebView chatDisplay;
    private Button sendButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        messageInput = findViewById(R.id.message_input);
        chatDisplay = findViewById(R.id.chat_display);
        sendButton = findViewById(R.id.send_button);

        chatDisplay.getSettings().setJavaScriptEnabled(true);
        chatDisplay.loadData("<div>Welcome to chat!</div>", "text/html", "UTF-8");

        sendButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String message = messageInput.getText().toString();
                // 漏洞点：直接拼接用户输入到HTML内容中
                String html = "<div>Message: " + message + "</div>";
                chatDisplay.loadData(html, "text/html", "UTF-8");
                messageInput.setText("");
            }
        });
    }
}

// 布局文件activity_chat.xml需要包含对应的控件
// <EditText android:id="@+id/message_input"/>
// <Button android:id="@+id/send_button"/>
// <WebView android:id="@+id/chat_display"/>