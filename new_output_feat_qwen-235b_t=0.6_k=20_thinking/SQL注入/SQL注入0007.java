package com.gamestudio.controller;

import com.gamestudio.service.GameItemService;
import com.gamestudio.common.ApiResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 游戏道具管理控制器
 * 提供道具批量删除接口
 */
@RestController
@RequestMapping("/api/items")
public class GameItemController {
    @Autowired
    private GameItemService gameItemService;

    /**
     * 批量删除道具接口
     * @param itemIds 待删除道具ID列表
     * @return 操作结果
     */
    @DeleteMapping("/batch")
    public ApiResult batchDeleteItems(@RequestBody List<String> itemIds) {
        if (itemIds == null || itemIds.isEmpty()) {
            return ApiResult.error("参数不能为空");
        }
        
        // 对ID格式进行简单校验（存在绕过可能）
        for (String id : itemIds) {
            if (!id.matches("\\\\d+")) {
                return ApiResult.error("包含非法ID格式");
            }
        }
        
        try {
            int count = gameItemService.deleteItems(itemIds);
            return ApiResult.success(count + "条记录已删除");
        } catch (Exception e) {
            return ApiResult.error("删除失败: " + e.getMessage());
        }
    }
}

package com.gamestudio.service;

import com.gamestudio.mapper.GameItemMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 游戏道具服务类
 * 处理道具删除业务逻辑
 */
@Service
public class GameItemService {
    @Autowired
    private GameItemMapper gameItemMapper;

    /**
     * 删除道具
     * @param itemIds 道具ID列表
     * @return 删除数量
     */
    public int deleteItems(List<String> itemIds) {
        if (itemIds.size() > 100) {
            throw new IllegalArgumentException("单次删除数量不能超过100");
        }
        
        // 将ID列表转换为逗号分隔字符串
        String idList = String.join(",", itemIds);
        
        // 调用Mapper执行删除
        return gameItemMapper.deleteItems(idList);
    }
}

package com.gamestudio.mapper;

import org.apache.ibatis.annotations.Mapper;

/**
 * 道具数据访问接口
 * 存在SQL注入漏洞的Mapper
 */
@Mapper
public interface GameItemMapper {
    /**
     * 删除指定ID的道具
     * @param ids ID列表字符串
     * @return 删除数量
     */
    int deleteItems(String ids);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.gamestudio.mapper.GameItemMapper">
    <!-- 漏洞点：直接拼接ID列表参数 -->
    <update id="deleteItems">
        DELETE FROM game_items
        WHERE id IN (${ids})
    </update>
</mapper>