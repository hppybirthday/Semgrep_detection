package com.example.app.controller;

import com.example.app.common.api.CommonResult;
import com.example.app.model.User;
import com.example.app.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户管理Controller
 */
@Controller
@Tag(name = "UserController", description = "用户管理")
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    @Operation(summary = "分页查询用户")
    @RequestMapping(value = "/list", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<List<User>> list(@RequestParam(value = "username", required = false) String username,
                                         @RequestParam(value = "mobile", required = false) String mobile,
                                         @RequestParam(value = "sort", required = false) String sort,
                                         @RequestParam(value = "order", required = false) String order) {
        List<User> users = userService.listUsers(username, mobile, sort, order);
        return CommonResult.success(users);
    }

    @Operation(summary = "获取用户详情")
    @RequestMapping(value = "/detail/{id}", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<User> detail(@PathVariable String id) {
        User user = userService.getUserById(id);
        return CommonResult.success(user);
    }
}