package com.example.mathsim.application;

import com.example.mathsim.domain.model.SimulationConfig;
import com.example.mathsim.domain.service.SimulationEngine;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.imageio.ImageIO;

@RestController
@RequestMapping("/simulations")
public class SimulationController {
    private final SimulationEngine simulationEngine;

    public SimulationController(SimulationEngine simulationEngine) {
        this.simulationEngine = simulationEngine;
    }

    @PostMapping("/run")
    public void runSimulation(@RequestParam String configUrl, HttpServletResponse response) {
        try {
            // 漏洞点：直接使用用户输入构造URI
            URI sourceUri = URI.create(configUrl);
            URL url = sourceUri.toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data source");
                return;
            }

            InputStream inputStream = connection.getInputStream();
            BufferedImage image = ImageIO.read(inputStream);
            
            // 模拟处理图像数据
            SimulationConfig config = simulationEngine.processImage(image);
            response.setContentType("application/json");
            response.getWriter().write(config.toJson());
            
        } catch (Exception e) {
            e.printStackTrace();
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            } catch (Exception ex) {
                // Ignore
            }
        }
    }
}

// 领域服务类
package com.example.mathsim.domain.service;

import com.example.mathsim.domain.model.SimulationConfig;
import java.awt.image.BufferedImage;

public class SimulationEngine {
    public SimulationConfig processImage(BufferedImage image) {
        // 模拟图像处理逻辑
        int width = image.getWidth();
        int height = image.getHeight();
        return new SimulationConfig("image-analysis", width * height, 0.95);
    }
}

// 领域实体类
package com.example.mathsim.domain.model;

public class SimulationConfig {
    private final String analysisType;
    private final int complexity;
    private final double accuracy;

    public SimulationConfig(String analysisType, int complexity, double accuracy) {
        this.analysisType = analysisType;
        this.complexity = complexity;
        this.accuracy = accuracy;
    }

    public String toJson() {
        return String.format("{\\"analysis\\":\\"%s\\", \\"complexity\\":%d, \\"accuracy\\":%.2f}", 
            analysisType, complexity, accuracy);
    }
}