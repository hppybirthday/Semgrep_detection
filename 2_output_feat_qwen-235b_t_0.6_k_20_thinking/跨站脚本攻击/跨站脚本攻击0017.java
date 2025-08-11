package com.iot.device.controller;

import com.iot.device.service.DeviceService;
import com.iot.device.model.Device;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/device")
public class DeviceController {
    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    @GetMapping("/add")
    public String showAddDeviceForm(Model model) {
        model.addAttribute("device", new Device());
        return "add-device";
    }

    @PostMapping("/add")
    public String addDevice(@ModelAttribute Device device) {
        deviceService.saveDevice(device);
        return "redirect:/device/list";
    }

    @GetMapping("/list")
    public String listDevices(Model model) {
        List<Device> devices = deviceService.getAllDevices();
        model.addAttribute("devices", devices);
        return "device-list";
    }

    @GetMapping("/{id}")
    public String viewDevice(@PathVariable Long id, Model model) {
        Device device = deviceService.getDeviceById(id);
        model.addAttribute("device", device);
        return "device-detail";
    }
}

// DeviceService.java
package com.iot.device.service;

import com.iot.device.model.Device;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DeviceService {
    private final List<Device> deviceRepository = new ArrayList<>();

    public void saveDevice(Device device) {
        deviceRepository.add(device);
    }

    public List<Device> getAllDevices() {
        return new ArrayList<>(deviceRepository);
    }

    public Device getDeviceById(Long id) {
        return deviceRepository.stream()
                .filter(d -> d.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Device not found"));
    }
}

// Device.java
package com.iot.device.model;

import lombok.Data;

@Data
public class Device {
    private Long id;
    private String name;
    private String status;
    private String firmwareVersion;
}

// add-device.html
<!--<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Add Device</title>
</head>
<body>
<h1>Add New Device</h1>
<form th:action="@{/device/add}" th:object="${device}" method="post">
    <div>
        <label>Device Name:</label>
        <input type="text" th:field="*{name}" required/>
    </div>
    <div>
        <label>Status:</label>
        <input type="text" th:field="*{status}" required/>
    </div>
    <button type="submit">Add Device</button>
</form>
</body>
</html>-->

// device-detail.html
<!--<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Device Detail</title>
</head>
<body>
<h1>Device Information</h1>
<div th:each="device : ${devices}">
    <p th:text="'Name: ' + ${device.name}"></p>
    <p th:text="'Status: ' + ${device.status}"></p>
</div>
</body>
</html>-->