package com.example.iot.controller;

import com.example.iot.data.DataPacket;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/device")
public class IoTDeviceController {

    @PostMapping("/upload")
    public String handleDataUpload(@RequestBody String payload) {
        try {
            byte[] data = Base64.getDecoder().decode(payload);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            DataPacket packet = (DataPacket) ois.readObject();
            ois.close();
            
            // 模拟处理设备数据
            return String.format("Received data from device %s: %s (Timestamp: %d)",
                packet.getDeviceId(), packet.getSensorData(), packet.getTimestamp());
        } catch (Exception e) {
            return "Error processing data: " + e.getMessage();
        }
    }

    @GetMapping("/status/{id}")
    public String checkDeviceStatus(@PathVariable String id) {
        return String.format("Device %s status: ONLINE | Last heartbeat: 2023-09-20 14:30:00", id);
    }
}

// ==================== Data Classes ====================

package com.example.iot.data;

import java.io.Serializable;
import java.util.Map;

public class DataPacket implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String deviceId;
    private Map<String, Object> sensorData;
    private long timestamp;
    private transient String validationToken; // 故意不序列化

    public DataPacket(String deviceId, Map<String, Object> sensorData, long timestamp) {
        this.deviceId = deviceId;
        this.sensorData = sensorData;
        this.timestamp = timestamp;
    }

    // Getters and setters
    public String getDeviceId() { return deviceId; }
    public Map<String, Object> getSensorData() { return sensorData; }
    public long getTimestamp() { return timestamp; }
    public String getValidationToken() { return validationToken; }
    public void setValidationToken(String token) { this.validationToken = token; }
}

// 模拟攻击者可利用的危险类（实际利用中可能来自第三方库）
class MaliciousPayload implements Serializable {
    private String command;
    
    public MaliciousPayload(String cmd) {
        this.command = cmd;
    }

    private void execCommand() {
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        execCommand();
    }
}