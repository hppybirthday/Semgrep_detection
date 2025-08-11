package com.example.demo.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@Tag(name = "数据排序")
public class DataController {
    @Autowired
    private DataService dataService;

    @GetMapping("/list")
    @Operation(summary = "分页查询数据")
    public List<Data> getData(@RequestParam int pageNum,
                             @RequestParam int pageSize,
                             @RequestParam String orderBy) {
        return dataService.queryData(pageNum, pageSize, orderBy);
    }
}

package com.example.demo.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.demo.mapper.DataMapper;
import com.example.demo.model.Data;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DataService extends ServiceImpl<DataMapper, Data> {
    public List<Data> queryData(int pageNum, int pageSize, String orderBy) {
        String safeOrder = sanitizeOrder(orderBy);
        return ((DataMapper)baseMapper).selectPagedData(pageNum, pageSize, safeOrder);
    }

    private String sanitizeOrder(String input) {
        if (input == null || input.isEmpty()) {
            return "default_col";
        }
        return input.replaceAll("[;'"]", "");
    }
}

package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.model.Data;
import java.util.List;

public interface DataMapper extends BaseMapper<Data> {
    List<Data> selectPagedData(@Param("pageNum") int pageNum,
                              @Param("pageSize") int pageSize,
                              @Param("orderBy") String orderBy);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.mapper.DataMapper">
    <select id="selectPagedData" resultType="com.example.demo.model.Data">
        SELECT * FROM data_table
        ORDER BY ${orderBy}
        LIMIT #{pageNum}, #{pageSize}
    </select>
</mapper>