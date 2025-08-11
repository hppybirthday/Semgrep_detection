package com.example.vulnerableapp;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.function.Consumer;

public class DeserializationActivity extends AppCompatActivity {
    private static final String TAG = "DeserializationActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_deserialization);

        EditText inputField = findViewById(R.id.serializedInput);
        Button deserializeBtn = findViewById(R.id.deserializeBtn);

        // 使用函数式编程处理点击事件
        deserializeBtn.setOnClickListener(v -> {
            String encodedData = inputField.getText().toString();
            try {
                byte[] serializedData = Base64.decode(encodedData, Base64.DEFAULT);
                Object result = unsafeDeserialize(serializedData);
                Toast.makeText(this, "Deserialized: " + result.toString(), Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Log.e(TAG, "Deserialization failed", e);
                Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    // 不安全的反序列化方法
    private Object unsafeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            // 直接反序列化未经验证的数据（漏洞点）
            return ois.readObject();
        }
    }

    // 模拟可被利用的恶意可序列化类
    public static class MaliciousPayload implements java.io.Serializable {
        private void readObject(java.io.ObjectInputStream stream)
                throws IOException, ClassNotFoundException {
            // 模拟恶意代码执行
            Runtime.getRuntime().exec("rm -rf /data/local/tmp/exploit");
        }
    }
}