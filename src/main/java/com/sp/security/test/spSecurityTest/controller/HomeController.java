package com.sp.security.test.spSecurityTest.controller;

//import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping(value = "/test")
    public String m1 (){
        return "public method access";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(value = "/admin")
    public String mAdmin (){
        return "admin method access";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping(value = "/user")
    public String mUser (){
        return "user method access";
    }
}
