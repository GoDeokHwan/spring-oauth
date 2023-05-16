package com.example.springoauth.domain.common.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @GetMapping("/main")
    public String main(Model model) {
        return "main";
    }
}
