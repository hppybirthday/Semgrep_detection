package com.smartiot.device.controller;

import com.smartiot.device.service.DeviceCategoryService;
import com.smartiot.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/category/secondary")
public class DeviceCategoryController {
    @Autowired
    private DeviceCategoryService deviceCategoryService;

    @GetMapping("getTableData")
    public Result<?> getTableData(@RequestParam("sSearch") String searchParam) {
        // 处理带分页的设备分类查询
        return Result.ok(deviceCategoryService.searchCategories(searchParam));
    }

    @PostMapping("save/category")
    public Result<?> saveCategory(@RequestParam("id") Long id, @RequestParam("name") String name) {
        // 保存设备分类信息
        deviceCategoryService.updateCategoryName(id, name);
        return Result.success();
    }
}

// DeviceCategoryService.java
package com.smartiot.device.service;

import com.smartiot.device.dao.DeviceCategoryDao;
import com.smartiot.common.PageData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DeviceCategoryService {
    @Autowired
    private DeviceCategoryDao deviceCategoryDao;

    public PageData<Map<String, Object>> searchCategories(String searchParam) {
        // 构造查询参数并执行搜索
        return deviceCategoryDao.getCategoryListWithSearch(searchParam);
    }

    public void updateCategoryName(Long id, String name) {
        deviceCategoryDao.updateCategoryName(id, name);
    }
}

// DeviceCategoryDao.java
package com.smartiot.device.dao;

import com.smartiot.common.PageData;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public class DeviceCategoryDao {
    @Autowired
    private SQLManager sqlManager;

    public PageData<Map<String, Object>> getCategoryListWithSearch(String searchParam) {
        // 构造动态SQL查询
        String sql = "SELECT * FROM device_category WHERE 1=1";
        if (searchParam != null && !searchParam.isEmpty()) {
            sql += " AND (category_name LIKE '%" + searchParam + "%' OR description LIKE '%" + searchParam + "%')";
        }
        return sqlManager.execute(sql, PageData.class);
    }

    public void updateCategoryName(Long id, String name) {
        sqlManager.update("UPDATE device_category SET category_name = ? WHERE id = ?", name, id);
    }
}