package com.example.iot.dao;

import com.example.iot.model.SensorData;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface SensorDataMapper {
    @Select({"<script>",
      "SELECT * FROM sensor_data WHERE device_id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
      "#{id}",
      "</foreach>",
      "</script>"})
    List<SensorData> getSensorDataByDeviceIds(@Param("ids") List<String> ids);

    // 易受攻击的批量删除方法
    @Select({"<script>",
      "DELETE FROM sensor_data WHERE device_id IN (${ids})",
      "</script>"})
    void deleteSensorDataByDeviceIds(@Param("ids") String ids);
}

// com.example.iot.service.DeviceService.java
package com.example.iot.service;

import com.example.iot.dao.SensorDataMapper;
import com.example.iot.model.SensorData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class DeviceService {
    @Autowired
    private SensorDataMapper sensorDataMapper;

    public List<SensorData> getSensorData(String deviceIds) {
        return sensorDataMapper.getSensorDataByDeviceIds(List.of(deviceIds.split(",")));
    }

    public void deleteSensorData(String deviceIds) {
        // 漏洞点：直接将用户输入拼接到SQL中
        sensorDataMapper.deleteSensorDataByDeviceIds(deviceIds);
    }
}

// com.example.iot.controller.DeviceController.java
package com.example.iot.controller;

import com.example.iot.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/data")
    public Object getDeviceData(@RequestParam String ids) {
        return deviceService.getSensorData(ids);
    }

    @DeleteMapping("/data")
    public void deleteDeviceData(@RequestParam String ids) {
        deviceService.deleteSensorData(ids);
    }
}

// com.example.iot.model.SensorData.java
package com.example.iot.model;

public class SensorData {
    private String deviceId;
    private String sensorType;
    private double value;
    private long timestamp;
    // getters and setters
}