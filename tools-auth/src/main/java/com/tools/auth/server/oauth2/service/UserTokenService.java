package com.tools.auth.server.oauth2.service;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Map;

public interface UserTokenService {

    //用户名密码模式获取token

    OAuth2AccessToken getUserToken(Principal principal, Map<String,String> params) throws HttpRequestMethodNotSupportedException;

    OAuth2AccessToken getMobileToken();
}
