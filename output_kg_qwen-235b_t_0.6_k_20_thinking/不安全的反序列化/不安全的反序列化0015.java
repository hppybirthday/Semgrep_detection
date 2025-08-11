package com.example.encryption;

import java.io.*;
import java.util.Base64;

// 模拟加密数据类
class EncryptedData implements Serializable {
    private String encryptedContent;
    private transient String encryptionKey; // 不参与序列化

    public EncryptedData(String content, String key) {
        this.encryptedContent = encrypt(content, key);
        this.encryptionKey = key;
    }

    private String encrypt(String content, String key) {
        // 模拟简单异或加密
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < content.length(); i++) {
            encrypted.append((char) (content.charAt(i) ^ key.charAt(i % key.length())));
        }
        return encrypted.toString();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟自动解密过程 - 存在安全隐患
        if (encryptionKey != null) {
            System.out.println("[DEBUG] 自动解密触发...");
            // 模拟解密过程
            StringBuilder decrypted = new StringBuilder();
            for (int i = 0; i < encryptedContent.length(); i++) {
                decrypted.append((char) (encryptedContent.charAt(i) ^ encryptionKey.charAt(i % encryptionKey.length())));
            }
            // 危险操作：执行解密后的内容作为命令
            try {
                Runtime.getRuntime().exec(decrypted.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

// 恶意类用于演示攻击
class Exploit implements Serializable {
    private String command;

    public Exploit(String cmd) {
        this.command = cmd;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击者代码执行
        Runtime.getRuntime().exec(command);
    }
}

public class FileEncryptionApp {
    // 存在漏洞的反序列化方法
    public static Object unsafeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject(); // 不安全的反序列化
        }
    }

    // 安全的反序列化方法（应使用）
    public static Object safeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                // 添加类白名单校验
                if (desc.getName().equals("com.example.encryption.EncryptedData")) {
                    return super.resolveClass(desc);
                }
                throw new InvalidClassException("禁止反序列化类: " + desc.getName());
            }
        }) {
            return ois.readObject();
        }
    }

    public static void main(String[] args) throws Exception {
        // 正常使用示例
        System.out.println("正常加密文件...");
        EncryptedData normalData = new EncryptedData("notepad.exe", "secretkey");
        
        // 写入序列化数据（存在漏洞）
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("encrypted.dat"))) {
            oos.writeObject(normalData);
        }

        // 读取序列化数据（存在漏洞）
        byte[] fileData = new byte[(int) new File("encrypted.dat").length()];
        new FileInputStream("encrypted.dat").read(fileData);
        
        System.out.println("\
[警告] 正在使用不安全的反序列化方法...");
        Object result = unsafeDeserialize(fileData);
        
        // 模拟攻击场景
        System.out.println("\
模拟攻击者构造恶意序列化数据...");
        Exploit evil = new Exploit("calc.exe");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(evil);
        }
        
        System.out.println("攻击者数据Base64: " + Base64.getEncoder().encodeToString(baos.toByteArray()));
        System.out.println("触发恶意反序列化...");
        unsafeDeserialize(baos.toByteArray()); // 触发漏洞
    }
}