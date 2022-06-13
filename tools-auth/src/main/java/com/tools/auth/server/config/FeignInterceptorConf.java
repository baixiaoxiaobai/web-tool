package com.tools.auth.server.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

/**
 * feign拦截器
 * 服务间鉴权处理，feigin调用解决token传递问题
 */
@Configuration
public class FeignInterceptorConf {

	/**
	 * 使用feign client访问别的微服务时，将access_token放入参数或者header ，Authorization:Bearer xxx
	 * 或者url?access_token=xxx
	 */
	@Bean
	public RequestInterceptor requestInterceptor() {
		RequestInterceptor requestInterceptor = new RequestInterceptor() {

			@Override
			public void apply(RequestTemplate template) {
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				if (authentication != null) {
					if (authentication instanceof OAuth2Authentication) {
						OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
						String access_token = details.getTokenValue();
						template.header("Authorization", OAuth2AccessToken.BEARER_TYPE + " " + access_token);
					}

				}
			}
		};

		return requestInterceptor;
	}
}
