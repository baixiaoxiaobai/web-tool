package com.tools.auth.server.oauth2.config;

import com.tools.common.core.utils.PermitUrlProperties;
import com.tools.common.core.utils.encrypt.PasswordEncorder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

/**
 * spring security配置
 * 
 * @author owen 624191343@qq.com
 * @version 创建时间：2017年11月12日 上午22:57:51 2017年10月16日
 *          在WebSecurityConfigurerAdapter不拦截oauth要开放的资源
 */
@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(PermitUrlProperties.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;
	// @Autowired
	// private LogoutSuccessHandler logoutSuccessHandler;
	@Autowired(required = false)
	private AuthenticationEntryPoint authenticationEntryPoint;
	@Autowired
	private UserDetailsService userDetailsService;

//	@Autowired
//	private PasswordEncoder passwordEncoder;
	
	//重写AES	加密
	@Autowired
	private PasswordEncorder passwordEncorder;

	@Autowired
	private OauthLogoutHandler oauthLogoutHandler;
	@Autowired
	private PermitUrlProperties permitUrlProperties ;
	
	/**	SecurityHandlerConfig.java 再次拦截处理
	 * @Description:	在WebSecurityConfigurerAdapter不拦截oauth要开放的资源----接口请求，
	 * 【接口允许不带access_toen访问】、跟application配置一样
	 * @date: 		2019年5月10日
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/oauth/user/login");//帐号密码登录
		web.ignoring().antMatchers("/oauth/user/fast-login");//快捷登录、注册
		web.ignoring().antMatchers("/oauth/third/login");//第三方登录
		web.ignoring().antMatchers(permitUrlProperties.getIgnored());
		
	}
	/**
	 * 认证管理
	 * 
	 * @return 认证管理对象
	 * @throws Exception
	 *             认证异常信息
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();

		http.authorizeRequests()
				.anyRequest().authenticated();
		http.formLogin().loginPage("/login.html").loginProcessingUrl("/user/login")
				.successHandler(authenticationSuccessHandler).failureHandler(authenticationFailureHandler);

		// 基于密码 等模式可以无session,不支持授权码模式
		if (authenticationEntryPoint != null) {
			http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		} else {
			// 授权码模式单独处理，需要session的支持，此模式可以支持所有oauth2的认证
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
		}

		http.logout().logoutSuccessUrl("/login.html")
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
				.addLogoutHandler(oauthLogoutHandler).clearAuthentication(true);

		//增加验证码处理---拦截请求
//		http.apply(validateCodeSecurityConfig) ;
		
		// http.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
		// 解决不允许显示在iframe的问题
		http.headers().frameOptions().disable();
		
		http.headers().cacheControl();

	}

	/**
	 * 全局用户信息
	 * 
	 * @param auth
	 *            认证管理
	 * @throws Exception
	 *             用户认证异常信息
	 */
	@Autowired
	public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncorder);
	}


}
