package com.example.controller;

import com.example.entity.User;
import com.example.model.LoginDto;
import com.example.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);
    @Autowired private UserService userService;

    @PostMapping("/signin")
    public ResponseEntity login(@RequestBody @Valid LoginDto loginDto) {
        String token = "";

        try {
            token = this.userService.signin(loginDto.getUsername(), loginDto.getPassword());
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
        }
        return ResponseEntity.ok(token);
    }

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody @Valid LoginDto loginDto){
        String token = "";

        try {
            token = this.userService.signup(new User(loginDto.getUsername(), loginDto.getPassword(),
                    loginDto.getRole(), loginDto.getFirstName(), loginDto.getLastName()));
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
        }
        return ResponseEntity.ok(token);
    }

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<User> getAllUsers() {
        return userService.getAll();
    }
}