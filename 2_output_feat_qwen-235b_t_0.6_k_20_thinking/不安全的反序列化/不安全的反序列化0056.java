package com.iot.device.controller;

import com.alibaba.fastjson.JSON;
import com.iot.device.service.DeviceDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * 设备数据上传接口
 * @author iot_dev
 */
@RestController
@RequestMapping("/api/device")
public class DeviceController {
    @Autowired
    private DeviceDataService deviceDataService;

    /**
     * 接收设备配置文件上传
     * @param file Excel配置文件
     * @return 操作结果
     */
    @PostMapping("/upload")
    public Map<String, Object> uploadDeviceConfig(@RequestParam("file") MultipartFile file) {
        return deviceDataService.processDeviceConfig(file);
    }
}

package com.iot.device.service;

import com.alibaba.fastjson.JSONObject;
import com.iot.device.util.ExcelUtils;
import com.iot.device.model.DeviceInfo;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

/**
 * 设备数据处理服务
 * @author iot_dev
 */
@Service
public class DeviceDataService {
    /**
     * 处理设备配置文件
     * @param file Excel文件
     * @return 处理结果
     */
    public Map<String, Object> processDeviceConfig(MultipartFile file) {
        try {
            // 解析Excel文件获取配置字符串
            String configJson = ExcelUtils.parseExcelToJson(file);
            
            // 将JSON字符串转换为设备信息对象
            DeviceInfo deviceInfo = JSON.parseObject(configJson, DeviceInfo.class);
            
            // 保存设备配置（模拟业务操作）
            Map<String, Object> result = new HashMap<>();
            result.put("status", "success");
            result.put("deviceName", deviceInfo.getDeviceName());
            return result;
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "配置处理失败");
            return error;
        }
    }
}

package com.iot.device.util;

import org.apache.poi.ss.usermodel.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;

/**
 * Excel文件处理工具类
 * @author iot_dev
 */
public class ExcelUtils {
    /**
     * 解析Excel文件为JSON字符串
     * @param file Excel文件
     * @return JSON格式字符串
     * @throws Exception 解析异常
     */
    public static String parseExcelToJson(MultipartFile file) throws Exception {
        try (InputStream is = file.getInputStream()) {
            Workbook workbook = WorkbookFactory.create(is);
            Sheet sheet = workbook.getSheetAt(0);
            
            // 读取第一行第一列的JSON配置字符串
            Row row = sheet.getRow(0);
            Cell cell = row.getCell(0);
            
            return cell.getStringCellValue();
        }
    }
}

package com.iot.device.model;

/**
 * 设备信息实体类
 * @author iot_dev
 */
public class DeviceInfo {
    private String deviceName;
    private String firmwareVersion;
    private int heartbeatInterval;
    
    // Getters and Setters
    public String getDeviceName() {
        return deviceName;
    }
    
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
    
    public String getFirmwareVersion() {
        return firmwareVersion;
    }
    
    public void setFirmwareVersion(String firmwareVersion) {
        this.firmwareVersion = firmwareVersion;
    }
    
    public int getHeartbeatInterval() {
        return heartbeatInterval;
    }
    
    public void setHeartbeatInterval(int heartbeatInterval) {
        this.heartbeatInterval = heartbeatInterval;
    }
}