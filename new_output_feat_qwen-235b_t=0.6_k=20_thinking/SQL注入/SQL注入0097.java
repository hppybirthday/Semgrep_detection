package com.example.app.controller;

import com.example.app.dto.OrderDTO;
import com.example.app.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @PostMapping("/batch")
    public String batchCreateOrders(@RequestBody List<OrderDTO> orders,
                                    @RequestParam(name = "sortField", required = false) String sortField) {
        if (sortField == null || sortField.trim().isEmpty()) {
            sortField = "id";
        }
        orderService.processOrders(orders, sortField);
        return "Orders processed";
    }
}

package com.example.app.dto;

public class OrderDTO {
    private Long productId;
    private Integer quantity;

    public Long getProductId() { return productId; }
    public void setProductId(Long productId) { this.productId = productId; }
    public Integer getQuantity() { return quantity; }
    public void setQuantity(Integer quantity) { this.quantity = quantity; }
}

package com.example.app.model;

public class Order {
    private Long id;
    private Long productId;
    private Integer quantity;

    public Order(Long productId, Integer quantity) {
        this.productId = productId;
        this.quantity = quantity;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getProductId() { return productId; }
    public void setProductId(Long productId) { this.productId = productId; }
    public Integer getQuantity() { return quantity; }
    public void setQuantity(Integer quantity) { this.quantity = quantity; }
}

package com.example.app.service;

import com.example.app.dto.OrderDTO;
import com.example.app.mapper.OrderMapper;
import com.example.app.model.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class OrderService {
    @Autowired
    private OrderMapper orderMapper;

    public void processOrders(List<OrderDTO> orderDTOs, String sortField) {
        List<Order> orders = orderDTOs.stream()
                .map(dto -> new Order(dto.getProductId(), dto.getQuantity()))
                .collect(Collectors.toList());

        orderMapper.batchInsert(orders);
        String query = constructDynamicQuery(sortField);
        orderMapper.getOrdersByCustomQuery(query);
    }

    private String constructDynamicQuery(String sortField) {
        return "SELECT * FROM orders ORDER BY " + sortField;
    }
}

package com.example.app.mapper;

import com.example.app.model.Order;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface OrderMapper {
    void batchInsert(List<Order> orders);

    @Select("${query}")
    List<Order> getOrdersByCustomQuery(@Param("query") String query);
}