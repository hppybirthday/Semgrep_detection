package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * 模拟消息接收器Activity
 * 存在不安全的反序列化漏洞
 */
public class MessageReceiverActivity extends Activity {
    private static final String TAG = "MessageReceiver";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_message_receiver);
        
        TextView messageView = findViewById(R.id.message_text);
        
        try {
            // 从Intent中获取序列化数据（存在安全风险）
            Intent intent = getIntent();
            byte[] serializedData = intent.getByteArrayExtra("serialized_message");
            
            if (serializedData != null) {
                // 不安全的反序列化操作
                Message message = (Message) deserialize(serializedData);
                
                // 显示解密后的消息
                messageView.setText(message.getContent());
                
                // 记录审计日志（防御式编程体现）
                Log.d(TAG, "Received message from: " + message.getSender());
            } else {
                Toast.makeText(this, "No message received", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            // 基础异常处理（防御式编程体现）
            Log.e(TAG, "Deserialization error: " + e.getMessage());
            Toast.makeText(this, "Failed to process message", Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * 不安全的反序列化方法
     */
    private Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        // 漏洞点：直接反序列化不可信数据
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    /**
     * 消息类（需要序列化传输）
     */
    static class Message implements Serializable {
        private static final long serialVersionUID = 1L;
        private String sender;
        private String content;
        
        public Message(String sender, String content) {
            this.sender = sender;
            this.content = content;
        }

        public String getSender() {
            return sender;
        }

        public String getContent() {
            return content;
        }
    }
}

// AndroidManifest.xml配置示例（部分）
/*
<activity android:name=".MessageReceiverActivity">
    <intent-filter>
        <action android:name="com.example.vulnerableapp.ACTION_RECEIVE_MESSAGE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
*/