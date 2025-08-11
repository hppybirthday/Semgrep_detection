package com.example.taskmanager.template;

import com.example.taskmanager.model.Task;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Dev Team
 * @date 2023/09/15
 */
public class TaskTemplateEngine {

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    @interface TemplateField {
        String value();
    }

    static class TemplateContext {
        @TemplateField("title")
        private String title;
        @TemplateField("description")
        private String description;
        @TemplateField("status")
        private String status;

        public TemplateContext(String title, String description, String status) {
            this.title = title;
            this.description = description;
            this.status = status;
        }
    }

    public static String renderTaskDetails(Task task) {
        StringBuilder html = new StringBuilder();
        html.append("<div class='task'>");
        html.append("<h2>#{title}</h2>");
        html.append("<p>Description: #{description}</p>");
        html.append("<span>Status: #{status}</span>");
        html.append("</div>");

        TemplateContext context = new TemplateContext(
            task.getTitle(),
            task.getDescription(),
            task.getStatus()
        );

        try {
            for (Field field : TemplateContext.class.getDeclaredFields()) {
                if (field.isAnnotationPresent(TemplateField.class)) {
                    field.setAccessible(true);
                    String placeholder = "#{$" + field.getAnnotation(TemplateField.class).value() + "}";
                    String value = (String) field.get(context);
                    html.replace(0, html.length(), html.toString(), placeholder, value);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return html.toString();
    }

    private static String replace(String html, String placeholder, String value) {
        return html.replace(placeholder, value);
    }

    public static void main(String[] args) {
        Task task = new Task();
        task.setTitle("<script>alert('xss')</script>");
        task.setDescription("Sample task description");
        task.setStatus("Pending");
        System.out.println(renderTaskDetails(task));
    }
}

// --- Model Classes ---
package com.example.taskmanager.model;

public class Task {
    private String title;
    private String description;
    private String status;

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}