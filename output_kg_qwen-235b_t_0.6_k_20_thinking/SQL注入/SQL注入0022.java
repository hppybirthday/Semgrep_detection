package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final JdbcTemplate jdbcTemplate;

    public DeviceController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // 模拟设备状态查询接口（存在SQL注入漏洞）
    @GetMapping("/status")
    public List<Map<String, Object>> getDeviceStatus(@RequestParam String deviceId) {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM device_status WHERE device_id = '" + deviceId + "'";
        
        // 使用函数式编程处理结果
        return jdbcTemplate.queryForList(sql).stream()
            .map(row -> (Map<String, Object>) row)
            .collect(Collectors.toList());
    }

    // 模拟设备控制接口（存在SQL注入漏洞）
    @PostMapping("/control")
    public String controlDevice(@RequestParam String deviceId, 
                              @RequestParam String command) {
        // 漏洞点：直接拼接SQL语句
        String sql = "UPDATE device_commands SET last_command = '" + command + 
                   "' WHERE device_id = '" + deviceId + "'";
        
        jdbcTemplate.update(sql);
        return "Command sent to device " + deviceId;
    }

    // 模拟设备数据采集接口（存在SQL注入漏洞）
    @GetMapping("/data")
    public List<Map<String, Object>> collectDeviceData(@RequestParam String queryTime) {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM sensor_data WHERE timestamp >= '" + queryTime + "'";
        
        return jdbcTemplate.queryForList(sql).stream()
            .map(row -> (Map<String, Object>) row)
            .collect(Collectors.toList());
    }

    // 初始化数据库表（仅用于演示）
    @GetMapping("/init")
    public String initDatabase() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS device_status (device_id VARCHAR(50) PRIMARY KEY, status VARCHAR(100))");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS device_commands (device_id VARCHAR(50) PRIMARY KEY, last_command VARCHAR(100))");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS sensor_data (id INT AUTO_INCREMENT PRIMARY KEY, timestamp DATETIME, value FLOAT)");
        return "Database initialized";
    }

    public static void main(String[] args) {
        SpringApplication.run(DeviceController.class, args);
    }
}