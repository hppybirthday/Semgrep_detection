package com.iot.example;

import java.io.*;
import java.net.*;
import java.util.Base64;

public class DeviceController {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        while (true) {
            Socket s = ss.accept();
            new Thread(() -> handleDevice(s)).start();
        }
    }

    static void handleDevice(Socket s) {
        try (ObjectInputStream ois = new ObjectInputStream(s.getInputStream())) {
            String action = (String) ois.readObject();
            
            if (action.equals("UPDATE")) {
                String data = (String) ois.readObject();
                DeviceInfo info = (DeviceInfo) deserialize(Base64.getDecoder().decode(data));
                System.out.println("Updating device: " + info.deviceId);
                // Simulate device update
            }
            
            if (action.equals("DATA")) {
                DeviceData data = (DeviceData) ois.readObject();
                System.out.println("Received sensor data: " + data.sensorValue);
                // Store data logic
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }
}

class DeviceInfo implements Serializable {
    String deviceId;
    String firmwareVersion;
    boolean authorized;
    
    public DeviceInfo(String id, String version) {
        this.deviceId = id;
        this.firmwareVersion = version;
    }
}

class DeviceData implements Serializable {
    String sensorType;
    double sensorValue;
    long timestamp;
    
    public DeviceData(String type, double value) {
        this.sensorType = type;
        this.sensorValue = value;
        this.timestamp = System.currentTimeMillis();
    }
}