package com.example.springoauth.domain.common.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.view.RedirectView;

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

    @GetMapping("/oauth/redirect")
    public RedirectView oauthLogin(
            @PathVariable String type,
            Model model) {
        return new RedirectView("/main");
    }
}
