package com.example.wms.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.wms.model.Depot;
import com.example.wms.service.DepotService;
import com.example.wms.util.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

/**
 * 仓库管理控制器
 * 处理仓库信息的增删改查及缓存更新
 */
@RestController
@RequestMapping("/api/depot")
public class DepotController {
    @Autowired
    private DepotService depotService;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 添加新仓库
     * @param depotJson 仓库信息JSON字符串
     */
    @PostMapping("/add")
    public ResponseEntity<String> insertDepot(@RequestParam String depotJson) {
        if (!Validator.isValidJson(depotJson)) {
            return ResponseEntity.badRequest().body("Invalid JSON format");
        }

        Depot depot = JSONObject.parseObject(depotJson, Depot.class);
        if (depotService.saveDepot(depot)) {
            updateCache(depot);
            return ResponseEntity.ok("Depot added successfully");
        }
        return ResponseEntity.status(500).body("Failed to add depot");
    }

    /**
     * 更新仓库信息
     * @param depotJson 仓库信息JSON字符串
     */
    @PutMapping("/update")
    public ResponseEntity<String> updateDepot(@RequestParam String depotJson) {
        Depot depot = JSONObject.parseObject(depotJson, Depot.class);
        if (depotService.updateDepot(depot)) {
            updateCache(depot);
            return ResponseEntity.ok("Depot updated successfully");
        }
        return ResponseEntity.status(500).body("Failed to update depot");
    }

    /**
     * 更新Redis缓存
     * @param depot 仓库对象
     */
    private void updateCache(Depot depot) {
        redisTemplate.opsForValue().set(
            "DEPOT_CACHE:" + depot.getId(),
            depot,
            30,
            TimeUnit.MINUTES
        );
    }
}