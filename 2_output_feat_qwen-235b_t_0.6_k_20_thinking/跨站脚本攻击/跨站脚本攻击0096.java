package com.example.app.location;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LocationSearchController {

    private final LocationService locationService = new LocationService();

    @GetMapping("/search")
    public String search(@RequestParam String locationName) {
        String displayContent = locationService.buildDisplayContent(locationName);
        return displayContent;
    }
}

class LocationService {

    String buildDisplayContent(String locationName) {
        validateName(locationName);
        return new HtmlUtils().formatLocationName(locationName);
    }

    private void validateName(String name) {
        // 校验名称长度（业务规则）
        if (name.length() > 100) {
            throw new IllegalArgumentException("名称长度超过限制");
        }
    }
}

class HtmlUtils {

    String formatLocationName(String name) {
        // 替换空格为HTML空格（业务需求）
        return name.replace(" ", "&nbsp;");
    }
}