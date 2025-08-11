package com.example.iot.device.controller;

import com.example.iot.device.model.DeviceConfig;
import com.example.iot.device.service.DeviceService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.context.webflux.SpringWebFluxContextUtils;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Device configuration controller handling IoT device registration and display
 * @author dev-team
 */
@Controller
@RequestMapping("/device")
public class DeviceController {
    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    /**
     * Device registration endpoint with potential XSS vulnerability
     * @param config Device configuration from user input
     * @return Redirect to device list
     */
    @PostMapping("/register")
    public String registerDevice(@ModelAttribute DeviceConfig config) {
        // Vulnerable operation: Directly storing user input without sanitization
        deviceService.saveDevice(config);
        return "redirect:/device/list";
    }

    /**
     * Device display endpoint with unsafe template rendering
     * @param id Device ID
     * @param model Template model
     * @return Template name
     */
    @GetMapping("/view/{id}")
    public String viewDevice(@PathVariable String id, Model model) {
        DeviceConfig device = deviceService.findById(id);
        // Vulnerable operation: Exposing raw user input to template context
        model.addAttribute("device", device);
        return "device-detail";
    }

    /**
     * JSONP API endpoint with XSS in JavaScript context
     * @param callback JSONP callback name
     * @param id Device ID
     * @return JSONP response with raw device data
     */
    @GetMapping(value = "/api/data", produces = "application/javascript")
    @ResponseBody
    public String getDeviceData(@RequestParam String callback, @RequestParam String id) {
        DeviceConfig device = deviceService.findById(id);
        // Vulnerable operation: Direct string concatenation in JSONP response
        return String.format("%s({\\"name\\":\\"%s\\",\\"value\\":\\"%s\\"})",
                           callback, device.getName(), device.getSensorValue());
    }

    /**
     * Template processing with unsafe dynamic content
     * @param model Template model
     * @return Template name
     */
    @GetMapping("/list")
    public String listDevices(Model model) {
        List<DeviceConfig> devices = deviceService.getAllDevices();
        // Vulnerable operation: Passing unsanitized device names to template
        model.addAttribute("devices", devices);
        return "device-list";
    }
}

// Service class with incomplete validation
package com.example.iot.device.service;

import com.example.iot.device.model.DeviceConfig;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class DeviceService {
    private final List<DeviceConfig> deviceStore = new ArrayList<>();

    public void saveDevice(DeviceConfig config) {
        // Weak validation: Only checks length but not special characters
        if (config.getName() != null && config.getName().length() < 256) {
            deviceStore.add(config);
        }
    }

    public DeviceConfig findById(String id) {
        return deviceStore.stream()
            .filter(d -> d.getId().equals(id))
            .findFirst()
            .orElseThrow();
    }

    public List<DeviceConfig> getAllDevices() {
        return List.copyOf(deviceStore);
    }
}

// Model class with user-controlled fields
package com.example.iot.device.model;

import lombok.Data;

@Data
public class DeviceConfig {
    private String id;
    private String name; // Vulnerable field: Device name from user input
    private String sensorValue; // Vulnerable field: Sensor label from user input
    private String location;
}

// Thymeleaf template with unsafe output (device-list.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Device List</title></head>
<body>
    <h1>Registered Devices</h1>
    <div th:each="device : ${devices}">
        <!-- Vulnerable operation: Raw output using th:utext -->
        <h2 th:utext="${device.name}"></h2>
        <p>Sensor Value: <span th:text="${device.sensorValue}"></span></p>
        <!-- Vulnerable operation: Inline script with raw data -->
        <script th:inline="javascript">
            /*<![CDATA[*/
            var deviceValue = /*[(${device.sensorValue})]*/ 'default';
            /*]]>*/
        </script>
    </div>
</body>
</html>
*/