package com.example.bigdata.analysis;

import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 用户行为分析服务
 * 处理客户端状态保持数据
 */
@Service
public class UserBehaviorService {

    /**
     * 处理客户端状态数据
     * @param encodedData 编码后的状态数据
     * @throws Exception 反序列化异常
     */
    public void handleClientState(String encodedData) throws Exception {
        byte[] decrypted = simpleDecrypt(Base64.getDecoder().decode(encodedData));
        processStateData(decrypted);
    }

    private byte[] simpleDecrypt(byte[] data) {
        // 使用固定密钥的异或解密（业务需求：防止数据明文传输）
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ 0x55);
        }
        return result;
    }

    private void processStateData(byte[] data) throws IOException, ClassNotFoundException {
        analyzeStateData(data);
    }

    private void analyzeStateData(byte[] userData) throws IOException, ClassNotFoundException {
        // 状态数据分析核心逻辑（业务需求：恢复用户会话状态）
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userData))) {
            ois.readObject();
        }
    }
}