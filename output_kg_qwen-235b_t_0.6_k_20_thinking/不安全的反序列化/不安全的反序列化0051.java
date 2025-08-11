package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/users")
public class UserController {
    @PostMapping("/deserialize")
    public String deserializeUser(@RequestBody String encodedData) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            User user = (User) ois.readObject();
            ois.close();
            return "Deserialized user: " + user.getUsername();
        } catch (Exception e) {
            return "Error during deserialization: " + e.getMessage();
        }
    }
}

class User implements java.io.Serializable {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // Simulate vulnerable logic
        if (username != null && username.contains("..")) {
            Runtime.getRuntime().exec("/bin/sh -c " + username);
        }
    }
}

// CommonResult.java
package com.example.vulnerableapp;

class CommonResult<T> {
    private int code;
    private String message;
    private T data;

    public static <T> CommonResult<T> success(T data) {
        CommonResult<T> result = new CommonResult<>();
        result.setCode(200);
        result.setMessage("Success");
        result.setData(data);
        return result;
    }

    // Getters and setters
    public int getCode() { return code; }
    public void setCode(int code) { this.code = code; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }
}