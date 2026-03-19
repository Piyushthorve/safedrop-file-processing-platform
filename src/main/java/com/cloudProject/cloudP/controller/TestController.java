package com.cloudProject.cloudP.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/public/ping")
    public String publicPing() {
        return "public ok";
    }

    @GetMapping("/secure/ping")
    public String securePing() {
        return "secure ok";
    }
}
