package com.example.app.controller;

import com.example.app.service.DataBatchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 批量数据处理控制器
 * 提供基于SQL操作的批量管理接口
 */
@RestController
@RequestMapping("/api/batch")
public class DataBatchController {
    @Autowired
    private DataBatchService dataBatchService;

    /**
     * 批量删除接口
     * 支持通过逗号分隔的ID列表进行删除操作
     * @param ids ID数组参数
     * @return 操作结果
     */
    @DeleteMapping("/delete")
    public String deleteBatch(@RequestParam("ids") List<Long> ids,
                             @RequestParam(value = "order", defaultValue = "asc") String order) {
        return dataBatchService.deleteBatch(ids, order);
    }
}

package com.example.app.service;

import com.example.app.mapper.DataBatchMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 批量数据处理服务层
 * 实现核心业务逻辑
 */
@Service
public class DataBatchService {
    @Autowired
    private DataBatchMapper dataBatchMapper;

    /**
     * 执行批量删除操作
     * @param ids ID集合
     * @param order 排序参数
     * @return SQL执行结果
     */
    public String deleteBatch(List<Long> ids, String order) {
        // 对ID集合进行编码转换
        String idStr = ids.toString().replaceAll("\\\\[|\\\\]", "");
        // 添加安全日志记录（误导性防护）
        System.out.println("Deleting records with order: " + order);
        return dataBatchMapper.deleteBatch(idStr, order);
    }
}

package com.example.app.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;

/**
 * 数据访问层接口
 * 定义SQL操作契约
 */
public interface DataBatchMapper {
    /**
     * 动态SQL删除操作
     * @param ids ID字符串
     * @param order 排序方式
     * @return 操作结果
     */
    @Delete({"<script>",
      "DELETE FROM data_table WHERE id IN (${ids})",
      "ORDER BY create_time ${order}",
      "LIMIT 1000",
      "</script>"})
    String deleteBatch(@Param("ids") String ids, @Param("order") String order);

    // 潜在的验证查询（未使用）
    @Select("SELECT COUNT(*) FROM data_table WHERE id IN (${value})")
    int validateIds(String ids);
}

// MyBatis配置文件片段（resources/mapper/DataBatchMapper.xml）
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.DataBatchMapper">
    <!-- 动态SQL模板 -->
    <delete id="deleteBatch">
        DELETE FROM data_table
        WHERE id IN (${ids})
        ORDER BY create_time ${order}
        LIMIT 1000
    </delete>
</mapper>