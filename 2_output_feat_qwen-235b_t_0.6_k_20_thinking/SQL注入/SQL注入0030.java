package com.example.inventory.controller;

import com.example.inventory.service.InventoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/inventory")
public class InventoryController {
    @Autowired
    private InventoryService inventoryService;

    @DeleteMapping("/delete")
    public boolean deleteItems(@RequestParam("ids") List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return false;
        }
        return inventoryService.removeItems(ids);
    }
}

// -------------------------------------------

package com.example.inventory.service;

import com.example.inventory.mapper.InventoryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class InventoryService {
    @Autowired
    private InventoryMapper inventoryMapper;

    public boolean removeItems(List<String> ids) {
        String idList = formatIdList(ids);
        return inventoryMapper.deleteByIds(idList) > 0;
    }

    private String formatIdList(List<String> ids) {
        // 校验并格式化ID列表
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            sb.append(ids.get(i));
            if (i < ids.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }
}

// -------------------------------------------

package com.example.inventory.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Param;

public interface InventoryMapper {
    @Delete({"<script>",
        "DELETE FROM inventory WHERE id IN (${ids})",
        "</script>"})
    int deleteByIds(@Param("ids") String ids);
}