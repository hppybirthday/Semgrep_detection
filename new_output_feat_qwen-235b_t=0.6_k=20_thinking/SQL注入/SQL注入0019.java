package com.example.order.controller;

import com.example.order.dto.OrderBatchDTO;
import com.example.order.service.OrderBatchService;
import com.example.order.common.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 批量订单处理Controller
 * 提供批量订单创建接口
 */
@RestController
@Tag(name = "OrderBatchController", description = "批量订单处理")
@RequestMapping("/api/order/batch")
public class OrderBatchController {
    @Autowired
    private OrderBatchService orderBatchService;

    @Operation(summary = "批量创建订单")
    @PostMapping("/create")
    public Result<Boolean> createOrderBatches(@RequestBody List<OrderBatchDTO> orderList) {
        if (orderList == null || orderList.isEmpty()) {
            return Result.failed("订单列表不能为空");
        }
        
        // 检查mainId格式（存在绕过可能）
        for (OrderBatchDTO order : orderList) {
            if (!isValidMainId(order.getMainId())) {
                return Result.failed("非法mainId格式");
            }
        }
        
        boolean result = orderBatchService.createOrderBatches(orderList);
        return result ? Result.success(true) : Result.failed("创建失败");
    }

    /**
     * 验证mainId格式（存在缺陷）
     * 仅检查首字符是否为数字
     */
    private boolean isValidMainId(String mainId) {
        if (mainId == null || mainId.isEmpty()) {
            return false;
        }
        return Character.isDigit(mainId.charAt(0));
    }
}

package com.example.order.service;

import com.example.order.dto.OrderBatchDTO;
import com.example.order.mapper.OrderBatchMapper;
import com.example.order.entity.OrderBatchEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OrderBatchService {
    @Autowired
    private OrderBatchMapper orderBatchMapper;

    public boolean createOrderBatches(List<OrderBatchDTO> orderList) {
        if (orderList.isEmpty()) {
            return false;
        }
        
        // 构建动态SQL参数
        StringBuilder valuesBuilder = new StringBuilder();
        for (int i = 0; i < orderList.size(); i++) {
            OrderBatchDTO order = orderList.get(i);
            valuesBuilder.append("('").append(order.getMainId()).append("')");
            if (i < orderList.size() - 1) {
                valuesBuilder.append(",");
            }
        }
        
        // 执行批量插入（存在SQL注入漏洞）
        return orderBatchMapper.batchInsert(valuesBuilder.toString()) > 0;
    }
}

package com.example.order.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Insert;

public interface OrderBatchMapper {
    /**
     * 批量插入订单（存在SQL注入漏洞）
     * 使用字符串拼接方式构建SQL
     */
    @Insert({"<script>",
        "INSERT INTO orders_batch (main_id) VALUES ",
        "${values}",
        "</script>"})
    int batchInsert(@Param("values") String values);
    
    // 安全版本（注释掉的正确实现）
    /*
    @Insert({"<script>",
        "INSERT INTO orders_batch (main_id) VALUES ",
        "<foreach collection='orderList' item='order' separator=','>",
        "(#{order.mainId})",
        "</foreach>",
        "</script>"})
    int safeBatchInsert(@Param("orderList") List<OrderBatchDTO> orderList);
    */
}

package com.example.order.dto;

import lombok.Data;

@Data
public class OrderBatchDTO {
    private String mainId; // 存在风险的字段
    private String orderNo;
    private Double amount;
}

package com.example.order.common;

import lombok.Data;

@Data
public class Result<T> {
    private int code;
    private String message;
    private T data;
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMessage("成功");
        result.setData(data);
        return result;
    }
    
    public static <T> Result<T> failed(String message) {
        Result<T> result = new Result<>();
        result.setCode(500);
        result.setMessage(message);
        return result;
    }
}
