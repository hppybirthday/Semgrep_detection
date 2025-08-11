package com.gamestudio.desktop.controller;

import com.github.pagehelper.PageHelper;
import com.gamestudio.desktop.dto.ItemDTO;
import com.gamestudio.desktop.service.ItemService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 游戏物品管理接口
 * 提供分页查询功能
 */
@RestController
@RequestMapping("/api/items")
@Tag(name = "ItemController", description = "游戏物品管理")
public class ItemController {

    @Autowired
    private ItemService itemService;

    @GetMapping
    @Operation(summary = "分页查询游戏物品")
    public List<ItemDTO> listItems(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortField,
            @RequestParam(required = false) String sortOrder) {

        return itemService.getItems(pageNum, pageSize, sortField, sortOrder);
    }
}

package com.gamestudio.desktop.service;

import com.github.pagehelper.PageHelper;
import com.gamestudio.desktop.dto.ItemDTO;
import com.gamestudio.desktop.mapper.ItemMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 游戏物品业务处理
 * 包含排序参数白名单校验逻辑
 */
@Service
public class ItemService {

    @Autowired
    private ItemMapper itemMapper;

    public List<ItemDTO> getItems(int pageNum, int pageSize, String sortField, String sortOrder) {
        String validatedField = validateSortField(sortField);
        String validatedOrder = validateSortOrder(sortOrder);
        String orderByClause = validatedField + " " + validatedOrder;
        
        PageHelper.startPage(pageNum, pageSize);
        PageHelper.orderBy(orderByClause); // 构造SQL排序子句
        
        return itemMapper.selectAll();
    }

    private String validateSortField(String field) {
        // 限制允许的排序字段
        if (field == null || field.isEmpty()) {
            return "name";
        }
        switch (field.toLowerCase()) {
            case "name":
            case "level":
            case "rarity":
                return field;
            default:
                return "name";
        }
    }

    private String validateSortOrder(String order) {
        if (order == null || order.isEmpty()) {
            return "ASC";
        }
        return order.equalsIgnoreCase("DESC") ? "DESC" : "ASC";
    }
}

package com.gamestudio.desktop.mapper;

import com.gamestudio.desktop.dto.ItemDTO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * 游戏物品数据访问接口
 */
@Mapper
public interface ItemMapper {
    List<ItemDTO> selectAll();
}