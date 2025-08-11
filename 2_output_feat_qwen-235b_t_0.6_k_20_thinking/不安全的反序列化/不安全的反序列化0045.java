package com.example.demo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/mock/dlglong")
public class VulnerableController {
    private final ObjectMapper mapper;

    public VulnerableController() {
        this.mapper = new ObjectMapper();
        // 启用非安全的多态类型处理
        this.mapper.enable(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY);
        TypeResolverBuilder<?> resolver = new ObjectMapper().getTypeResolverBuilder();
        this.mapper.setTypeResolverBuilder(resolver);
    }

    @PostMapping("/getDdjhData")
    public ResponseEntity<?> processQueryParams(@RequestBody Map<String, String> payload) throws JsonProcessingException {
        String queryParam = payload.get("superQueryParams");
        if (queryParam == null || queryParam.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        // 反序列化不可信数据
        Object deserialized = mapper.readValue(queryParam, Object.class);
        // 模拟业务逻辑中的对象处理
        if (deserialized instanceof Map) {
            processMapData((Map<?, ?>) deserialized);
        }
        return ResponseEntity.ok("Processed");
    }

    private void processMapData(Map<?, ?> dataMap) {
        // 模拟缓存存储操作
        if (dataMap.containsKey("cacheKey")) {
            String key = dataMap.get("cacheKey").toString();
            // 触发嵌套对象处理
            if (dataMap.get(key) instanceof Map) {
                processMapData((Map<?, ?>) dataMap.get(key));
            }
        }
    }
}