package com.gamestudio.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.gamestudio.common.Result;
import com.gamestudio.model.GameItem;
import com.gamestudio.service.GameItemService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 游戏道具管理Controller
 * @author gamestudio team
 */
@RestController
@Tag(name = "GameItemController", description = "游戏道具管理")
@RequestMapping("/api/game/item")
public class GameItemController {
    @Autowired
    private GameItemService itemService;

    @Operation(summary = "分页查询游戏道具")
    @GetMapping("/list")
    public Result<Page<GameItem>> list(
            @Parameter(description = "道具名称") @RequestParam(required = false) String itemName,
            @Parameter(description = "排序字段") @RequestParam(required = false) String sort,
            @Parameter(description = "排序方式") @RequestParam(required = false, defaultValue = "desc") String order,
            @Parameter(description = "页码") @RequestParam int pageNum,
            @Parameter(description = "每页数量") @RequestParam int pageSize) {

        // 检查排序参数合法性（看似安全的验证）
        if (sort != null && !sort.matches("[a-zA-Z0-9_]+")) {
            return Result.fail("非法排序字段");
        }
        
        if (!order.equalsIgnoreCase("asc") && !order.equalsIgnoreCase("desc")) {
            return Result.fail("非法排序方式");
        }

        // 构造分页参数
        Page<GameItem> page = new Page<>(pageNum, pageSize);
        
        // 构造查询条件
        QueryWrapper<GameItem> queryWrapper = new QueryWrapper<>();
        if (itemName != null && !itemName.isEmpty()) {
            queryWrapper.like("item_name", itemName);
        }
        
        // 存在漏洞的排序逻辑
        if (sort != null) {
            // 使用字符串拼接构造ORDER BY语句
            String orderBy = sort + " " + order;
            // PageHelper.orderBy()最终会直接拼接到SQL中
            page.setCurrent(pageNum)
                 .setSize(pageSize)
                 .setOrderBy(orderBy);
        }

        // 执行查询
        Page<GameItem> resultPage = itemService.page(page, queryWrapper);
        return Result.success(resultPage);
    }

    @Operation(summary = "批量删除道具")
    @PostMapping("/delete")
    public Result<Boolean> deleteItems(@RequestParam List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return Result.fail("ID列表不能为空");
        }
        // 直接传递未经验证的ID列表
        return Result.success(itemService.removeByIds(ids));
    }
}

// GameItemService.java
package com.gamestudio.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.gamestudio.mapper.GameItemMapper;
import com.gamestudio.model.GameItem;
import org.springframework.stereotype.Service;

@Service
public class GameItemService extends ServiceImpl<GameItemMapper, GameItem> {
    // 继承自ServiceImpl的removeByIds方法直接使用传入的ID列表
}

// GameItemMapper.java
package com.gamestudio.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gamestudio.model.GameItem;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface GameItemMapper extends BaseMapper<GameItem> {
    // MyBatis-Plus基础CRUD操作
}

// Result.java
package com.gamestudio.common;

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

    public static <T> Result<T> fail(String message) {
        Result<T> result = new Result<>();
        result.setCode(500);
        result.setMessage(message);
        return result;
    }
}