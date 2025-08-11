package com.example.mobileapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 模拟移动应用中用户配置管理模块
 * 存在不安全的反序列化漏洞
 */
public class UserProfileManager {
    private static final String TAG = "UserProfileManager";
    private static final String PREFS_NAME = "user_profiles";
    private static final String KEY_USER_DATA = "serialized_user_data";

    private Context context;

    public UserProfileManager(Context context) {
        this.context = context;
    }

    /**
     * 从SharedPreferences加载用户数据（存在漏洞的反序列化）
     */
    public List<UserProfile> loadUserProfiles() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String encodedData = prefs.getString(KEY_USER_DATA, null);

        if (encodedData == null) {
            return new ArrayList<>();
        }

        try {
            // 漏洞点：直接反序列化不可信数据
            byte[] data = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 强制类型转换前未进行类型校验
            Object obj = ois.readObject();
            
            if (obj instanceof List) {
                // 二次漏洞：未验证集合内的元素类型
                return (List<UserProfile>) obj;
            }
            
            return new ArrayList<>();
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to deserialize user profiles", e);
            return new ArrayList<>();
        }
    }

    /**
     * 保存用户数据到SharedPreferences
     */
    public void saveUserProfiles(List<UserProfile> profiles) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(profiles);
            oos.close();
            
            String encodedData = Base64.getEncoder().encodeToString(baos.toByteArray());
            SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(KEY_USER_DATA, encodedData);
            editor.apply();
            
        } catch (IOException e) {
            Log.e(TAG, "Failed to serialize user profiles", e);
        }
    }

    /**
     * 用户配置类 - 可序列化对象
     */
    public static class UserProfile implements Serializable {
        private String username;
        private String email;
        private int loginCount;

        public UserProfile(String username, String email) {
            this.username = username;
            this.email = email;
        }

        // Getters and setters
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public int getLoginCount() { return loginCount; }
        public void incrementLogin() { loginCount++; }
    }

    /**
     * 模拟外部数据注入攻击
     * 用于演示攻击者如何构造恶意数据
     */
    public void simulateAttack(byte[] maliciousData) {
        try {
            // 攻击者控制的输入数据
            ByteArrayInputStream bais = new ByteArrayInputStream(maliciousData);
            ObjectInputStream ois = new ObjectInputStream(bais);
            ois.readObject(); // 直接触发反序列化漏洞
            
        } catch (Exception e) {
            Log.e(TAG, "Attack simulation failed", e);
        }
    }

    /**
     * 验证输入数据的类型（防御示例）
     * 但实际代码中未被使用
     */
    private boolean isValidProfileList(Object obj) {
        if (!(obj instanceof List)) {
            return false;
        }
        
        for (Object item : (List<?>) obj) {
            if (!(item instanceof UserProfile)) {
                return false;
            }
        }
        
        return true;
    }
}