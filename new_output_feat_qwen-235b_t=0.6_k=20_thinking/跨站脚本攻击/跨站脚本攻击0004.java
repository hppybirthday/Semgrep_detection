package com.example.iot.controller;

import com.example.iot.model.Device;
import com.example.iot.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/devices")
public class DeviceController {
    
    @Autowired
    private DeviceService deviceService;

    @GetMapping
    public String listDevices(Model model) {
        List<Device> devices = deviceService.getAllDevices();
        model.addAttribute("devices", devices);
        return "device-list";
    }

    @PostMapping
    public String addDevice(@RequestParam String name, @RequestParam String location) {
        Device device = new Device();
        device.setName(name);
        device.setLocation(location);
        deviceService.saveDevice(device);
        return "redirect:/devices";
    }

    @GetMapping("/api")
    @ResponseBody
    public List<Device> getDevicesJson() {
        return deviceService.getAllDevices();
    }
}

package com.example.iot.service;

import com.example.iot.model.Device;
import com.example.iot.repository.DeviceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DeviceService {
    
    @Autowired
    private DeviceRepository deviceRepository;

    public List<Device> getAllDevices() {
        return deviceRepository.findAll();
    }

    public void saveDevice(Device device) {
        // 模拟错误的清理逻辑：认为前端已处理
        deviceRepository.save(device);
    }
}

package com.example.iot.repository;

import com.example.iot.model.Device;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceRepository extends JpaRepository<Device, Long> {
}

package com.example.iot.model;

import jakarta.persistence.*;

@Entity
public class Device {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    private String location;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
}

// Thymeleaf模板 device-list.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Devices</title></head>
<body>
    <h1>Device List</h1>
    <div th:each="device : ${devices}">
        <p>Device: <span th:text="${device.name}"></span></p>
        <p>Location: <span th:text="${device.location}"></span></p>
    </div>
</body>
</html>
*/