package com.gamestudio.desktop.controller;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 玩家道具管理控制器
 * Created by gamestudio on 2023/10/15.
 */
@RestController
@RequestMapping("/api/player/item")
public class PlayerItemController {
    @Resource
    private PlayerItemService playerItemService;

    /**
     * 批量删除道具（存在安全缺陷）
     * @param aids 道具ID数组
     * @return 删除结果
     */
    @DeleteMapping("/batch")
    public Result<Boolean> deleteItems(@RequestParam("aids") String[] aids) {
        if (aids == null || aids.length == 0) {
            return Result.fail("参数不能为空");
        }
        // 校验道具ID格式
        List<String> validIds = Arrays.stream(aids)
                .filter(id -> id.matches("\\d+"))
                .collect(Collectors.toList());
        
        if (validIds.isEmpty()) {
            return Result.fail("无效道具ID");
        }
        
        boolean result = playerItemService.deleteItems(validIds.toArray(new String[0]));
        return Result.success(result);
    }

    static class Result<T> {
        private final T data;
        private final boolean success;
        private final String message;

        private Result(T data, boolean success, String message) {
            this.data = data;
            this.success = success;
            this.message = message;
        }

        public static <T> Result<T> success(T data) {
            return new Result<>(data, true, "操作成功");
        }

        public static <T> Result<T> fail(String message) {
            return new Result<>(null, false, message);
        }
    }
}

class PlayerItemService extends ServiceImpl<PlayerItemMapper, PlayerItem> {
    /**
     * 执行道具删除逻辑
     * @param aids 道具ID数组
     * @return 删除结果
     */
    boolean deleteItems(String[] aids) {
        String idList = String.join(",", Arrays.asList(aids));
        return baseMapper.deleteByItemIds(idList) > 0;
    }
}

class PlayerItemMapper implements BaseMapper<PlayerItem> {
    /**
     * 自定义删除方法（存在SQL拼接问题）
     * @param ids ID列表字符串
     * @return 影响记录数
     */
    @Delete({"<script>",
            "DELETE FROM player_item WHERE item_id IN (${ids})",
            "</script>"})
    int deleteByItemIds(String ids);
}

class PlayerItem {
    private Long itemId;
    private String itemName;
    // 其他字段省略
}