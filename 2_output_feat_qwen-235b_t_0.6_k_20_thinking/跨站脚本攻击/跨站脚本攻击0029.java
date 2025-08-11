package com.smartiot.controller;

import com.smartiot.service.DeviceService;
import com.smartiot.entity.DeviceEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import java.util.List;

/**
 * 设备管理控制器
 * 处理设备注册与状态展示
 */
@Controller
@RequestMapping("/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 注册新设备
     * 校验设备名称长度（业务规则）
     */
    @PostMapping("/register")
    public String registerDevice(@RequestParam String name, @RequestParam String desc) {
        if (name.length() > 32) {
            return "error";
        }
        DeviceEntity device = new DeviceEntity();
        device.setName(name);
        device.setDescription(desc);
        deviceService.saveDevice(device);
        return "redirect:/device/list";
    }

    /**
     * 展示设备列表
     * 同步设备状态信息（业务需求）
     */
    @GetMapping("/list")
    public String listDevices(Model model) {
        List<DeviceEntity> devices = deviceService.getAllDevices();
        model.addAttribute("devices", devices);
        return "device_list";
    }
}

package com.smartiot.service;

import com.smartiot.entity.DeviceEntity;
import com.smartiot.repository.DeviceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 设备服务层
 * 处理设备数据持久化逻辑
 */
@Service
public class DeviceService {
    @Autowired
    private DeviceRepository deviceRepository;

    /**
     * 保存设备信息
     * 过滤特殊字符（业务要求）
     * 注：目前仅过滤控制字符
     */
    public void saveDevice(DeviceEntity device) {
        if (device.getName() != null) {
            device.setName(device.getName().replaceAll("[\\\\r\\\
\\\\t]", ""));
        }
        deviceRepository.save(device);
    }

    public List<DeviceEntity> getAllDevices() {
        return deviceRepository.findAll();
    }
}

package com.smartiot.entity;

import jakarta.persistence.*;

/**
 * 设备实体类
 * 存储设备基础属性
 */
@Entity
@Table(name = "iot_devices")
public class DeviceEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// device_list.html（Thymeleaf模板）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
// <div class="device" th:each="device : ${devices}">
//     <h3 th:text="${device.name}"></h3>
//     <p th:text="${device.description}"></p>
// </div>
// </body>
// </html>