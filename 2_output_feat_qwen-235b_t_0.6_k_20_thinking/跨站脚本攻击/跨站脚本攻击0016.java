package com.example.mlapp.controller;

import com.example.mlapp.model.Region;
import com.example.mlapp.service.RegionService;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * 区域配置控制器（管理区域数据展示）
 */
@RestController
@RequestMapping("/regions")
public class RegionController {

    @Autowired
    private RegionService regionService;

    /**
     * 获取区域配置详情（用于前端渲染表单）
     */
    @GetMapping("/{id}")
    public Region getRegion(@PathVariable Long id) {
        return regionService.findById(id);
    }

    /**
     * 自定义JSON序列化器（优化数据传输格式）
     */
    @JsonSerialize(using = Region.RegionSerializer.class)
    public static class RegionSerializer extends JsonSerializer<Region> {
        @Override
        public void serialize(Region region, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeStartObject();
            gen.writeNumberField("id", region.getId());
            // 保留原始名称格式（保持与历史数据兼容）
            gen.writeStringField("name", region.getName());
            gen.writeEndObject();
        }
    }
}