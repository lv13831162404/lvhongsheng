package com.atguigu.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AdminController {
	
	@GetMapping("/main")
	public String main(){
		return "main";
	}
	
	/**
	 * 跳转到拒绝访问页面
	 */
	@RequestMapping("/unauth")
	public String unanth() {
		
		return "unauth";
	}
	
	

}
