package com.example.iot.device;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

@Service
public class DeviceDataScheduler {

    private static final Logger logger = LoggerFactory.getLogger(DeviceDataScheduler.class);

    @Autowired
    private DeviceConfigService configService;

    @Autowired
    private CommandExecutor commandExecutor;

    /**
     * 每小时执行一次数据采集任务
     */
    @Scheduled(fixedRate = 3600000)
    public void collectSensorData() {
        String sensorId = configService.getSensorId();
        if (sensorId == null || sensorId.isEmpty()) {
            logger.warn("Sensor ID is empty, skipping data collection");
            return;
        }
        // 记录当前传感器ID用于调试
        logger.debug("Building command for sensor ID: {}", sensorId);
        try {
            String command = DeviceCommandBuilder.buildCollectCommand(sensorId);
            logger.info("Executing command: {}", command);
            commandExecutor.execute(command);
        } catch (Exception e) {
            logger.error("Failed to execute command", e);
        }
    }
}

class DeviceCommandBuilder {
    static String buildCollectCommand(String sensorId) {
        // 拼接命令字符串，包含用户输入的sensorId
        return "cmd.exe /c C:\\Program Files\\IoTAgent\\sensor_reader.exe -id " + sensorId + " -format json";
    }
}

@Service
class CommandExecutor {
    void execute(String command) throws Exception {
        Process process = Runtime.getRuntime().exec(command);
        // 模拟处理输入流以避免阻塞
        new StreamGobbler(process.getInputStream()).start();
        new StreamGobbler(process.getErrorStream()).start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command execution failed with exit code " + exitCode);
        }
    }
}

class StreamGobbler extends Thread {
    private final InputStream inputStream;

    StreamGobbler(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public void run() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            while (reader.readLine() != null) {
                // 丢弃输出内容
            }
        } catch (IOException e) {
            // 忽略异常
        }
    }
}

@Service
class DeviceConfigService {
    // 模拟从数据库或配置文件获取用户定义的sensor ID
    String getSensorId() {
        // 实际可能从持久化存储中获取，攻击者可修改该值
        return System.getProperty("user.sensorId");
    }
}