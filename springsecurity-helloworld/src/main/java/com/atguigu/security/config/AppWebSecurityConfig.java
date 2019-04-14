package com.atguigu.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
@Configurable//声明当前类为配置类，相当于XML文件
@EnableWebSecurity//开启Web环境下的SpringSecurity功能
@EnableGlobalMethodSecurity(prePostEnabled=true)//开启全局的细粒度方法级别的权限控制功能
public class AppWebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	/**
	 * 重写configure(HttpSecurity http)方法
	 * 放行首页、静态资源、登录页
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//默认的认证（没有认证所有页面都不让访问）
		//super.configure(http);
		
		//放行首页和静态资源
		http.authorizeRequests()
			.antMatchers("/layui/**","/index.jsp").permitAll()//要放行的静态资源
//			.antMatchers("/level1/**").hasRole("学徒")//给学徒权限授权，拥有学徒角色，就能访问level1
//			.antMatchers("/level2/**").hasAnyRole("宗师","大师")
//			.antMatchers("/level3/**").access("hasRole('宗师') and hasAuthority('VIP') or hasRole('长老')")
			.anyRequest().authenticated();//剩余的其他资源必须认证过才能访问
		
		//未授权的资源自动去往登录页面
		http.formLogin()	//开启默认登录页
			.loginPage("/index.jsp")	//去往指定的登录页面
			.defaultSuccessUrl("/main")	//登录成功，去往主页
			.permitAll();	//放行
		
		//注销方法一：
//		http.logout()
//			.logoutSuccessUrl("/index.jsp")	//注销后去往指定页面
//			.permitAll();	//放行
		
		//注销方法二：
		http.logout().logoutSuccessHandler(new LogoutSuccessHandler() {

			@Override
			public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				//获取session
				HttpSession session = request.getSession(false);
				//判断session是否为空
				if(session != null) {
					session.invalidate();
				}
				response.sendRedirect(request.getContextPath()+"/index.jsp");
			}
		});
		
		
		//拒绝访问页面的处理
//		http.exceptionHandling().accessDeniedPage("/unauth");
		
		//自定义拒绝访问页面的处理
		http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {

			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException) throws IOException, ServletException {
				
				//获取异常信息放到request中
				request.setAttribute("message", accessDeniedException.getMessage());
				
				//跳转页面
				request.getRequestDispatcher("/WEB-INF/views/unauth.jsp").forward(request, response);
				
			}
			
		});
		
		
		
		//记住我功能：remember-me，内存版
//		http.rememberMe();
		
		//记住我功能：数据库版
		JdbcTokenRepositoryImpl jdbcTokenRepositoryImpl = new JdbcTokenRepositoryImpl();
		
		jdbcTokenRepositoryImpl.setDataSource(dataSource);
		
		http.rememberMe().tokenRepository(jdbcTokenRepositoryImpl);
		
	}
	
	/**
	 * 重写configure(AuthenticationManagerBuilder auth)方法
	 * 自定义认证用户信息
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//默认的认证
		//super.configure(auth);
		
		//认证用户
//		auth.inMemoryAuthentication()
//			.withUser("zhangsan").password("123456")//认证用户信息
//			.roles("学徒");	//给用户分配角色
		
		//认证用户以及所拥有的权限
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
			
	}
	
}
