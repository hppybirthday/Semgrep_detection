package com.example.demo;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Controller层
@RestController
@RequestMapping("/data")
public class DataCleanController {
    @Autowired
    private DataService dataService;

    @GetMapping("/clean")
    public PageInfo<CleanData> cleanData(
        @RequestParam String ids,
        @RequestParam(required = false) String sortField) {
        
        // 漏洞点：直接拼接用户输入到PageHelper.orderBy
        if (sortField != null && !sortField.isEmpty()) {
            PageHelper.orderBy(sortField);
        }
        
        return dataService.cleanData(ids);
    }
}

// Service层
@Service
class DataService {
    @Autowired
    private DataMapper dataMapper;

    public PageInfo<CleanData> cleanData(String ids) {
        // 漏洞点：直接将用户输入拼接到SQL查询中
        List<CleanData> dataList = dataMapper.selectByIds("'" + ids.replace(",", "','") + "'");
        return new PageInfo<>(dataList);
    }
}

// DAO层接口
interface DataMapper extends BaseMapper<CleanData> {
    List<CleanData> selectByIds(@Param("ids") String ids);
}

// MyBatis XML映射文件
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.DataMapper">
  <select id="selectByIds" resultType="com.example.demo.CleanData">
    SELECT * FROM clean_data
    WHERE id IN (${ids})
    ORDER BY create_time DESC
  </select>
</mapper>

// 实体类
class CleanData {
    private Long id;
    private String content;
    private java.util.Date createTime;
    // getter/setter省略
}