package com.iot.device.controller;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * IoT设备配置管理器
 * 模拟智能设备接收远程配置的场景
 */
public class IoTDeviceController {
    private static final Logger logger = Logger.getLogger("IoTDeviceController");
    private static final String TRUSTED_CONFIG_CLASS = "com.iot.device.model.DeviceConfig";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8081)) {
            logger.info("设备控制器启动在8081端口");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            logger.severe("服务器异常: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            Object rawConfig = ois.readObject();
            
            // 防御式验证：检查类名
            if (!rawConfig.getClass().getName().equals(TRUSTED_CONFIG_CLASS)) {
                logger.warning("检测到非法配置类型: " + rawConfig.getClass().getName());
                return;
            }
            
            // 强制类型转换（假设验证有效）
            DeviceConfig config = (DeviceConfig) rawConfig;
            
            // 处理设备控制逻辑
            processDeviceCommand(config);
            
        } catch (IOException | ClassNotFoundException e) {
            logger.warning("反序列化异常: " + e.getMessage());
        } catch (ClassCastException e) {
            logger.warning("类型转换失败: " + e.getMessage());
        }
    }

    private static void processDeviceCommand(DeviceConfig config) {
        logger.info("应用新配置: " + config.toString());
        // 实际设备控制逻辑
        if ("REBOOT".equals(config.getCommand())) {
            logger.info("执行设备重启操作...");
        }
    }
}

/**
 * 设备配置类
 * 支持序列化传输的配置对象
 */
class DeviceConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    private String deviceId;
    private String command;
    private String payload;
    
    // 模拟危险的反序列化回调
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟存在漏洞的逻辑
        if (payload != null && payload.startsWith("MAGIC:")) {
            String[] cmd = payload.substring(6).split(" ");
            try {
                Runtime.getRuntime().exec(cmd);
            } catch (IOException e) {
                // 静默失败可能导致漏洞隐蔽
            }
        }
    }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    
    @Override
    public String toString() {
        return String.format("DeviceConfig{deviceId='%s', command='%s'}", deviceId, command);
    }
}