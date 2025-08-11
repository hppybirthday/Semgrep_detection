package com.example.crypto.controller;

import com.example.crypto.service.EncryptionService;
import com.example.crypto.model.EncryptionConfig;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/crypto")
public class ConfigController {
    private final EncryptionService encryptionService;

    public ConfigController(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @GetMapping("/config")
    public String getConfig(Model model) {
        model.addAttribute("config", encryptionService.getActiveConfig());
        return "config";
    }

    @PostMapping("/update")
    @ResponseBody
    public String updateConfig(@RequestParam String algoName, @RequestParam String algoMode) {
        encryptionService.updateAlgorithm(algoName, algoMode);
        return "{\"status\":\"success\"}";
    }
}

package com.example.crypto.service;

import com.example.crypto.model.EncryptionConfig;
import org.springframework.stereotype.Service;

@Service
public class EncryptionService {
    private EncryptionConfig activeConfig = new EncryptionConfig("AES", "CBC");

    public EncryptionConfig getActiveConfig() {
        return activeConfig;
    }

    public void updateAlgorithm(String algoName, String algoMode) {
        // 漏洞点：直接存储用户输入未做净化处理
        activeConfig = new EncryptionConfig(algoName, algoMode);
    }
}

package com.example.crypto.model;

import lombok.Data;

@Data
public class EncryptionConfig {
    private String algorithmName;
    private String mode;

    public EncryptionConfig(String algorithmName, String mode) {
        this.algorithmName = algorithmName;
        this.mode = mode;
    }
}

// config.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head>
//     <title>Crypto Config</title>
//     <script th:inline="javascript">
//         /*<![CDATA[*/
//         function initCrypto() {
//             /* The algorithm name is stored in variable below */
//             var ALGO_NAME = /*[(${config.algorithmName})]*/ 'AES';
//             var ALGO_MODE = /*[(${config.mode})]*/ 'CBC';
//             console.log('Initializing ' + ALGO_NAME + ' in ' + ALGO_MODE + ' mode');
//         }
//         /*]]>*/
//     </script>
// </head>
// <body onload="initCrypto()">
//     <h2 th:inline="text">Current Algorithm: [[${config.algorithmName}]]</h2>
//     <form method="post" action="/crypto/update">
//         <input type="text" name="algoName" placeholder="Algorithm Name"/>
//         <input type="text" name="algoMode" placeholder="Mode"/>
//         <button type="submit">Update</button>
//     </form>
// </body>
// </html>