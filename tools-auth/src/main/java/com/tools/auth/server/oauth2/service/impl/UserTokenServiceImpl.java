//package com.tools.auth.server.oauth2.service.impl;
//
//import com.jx3.wbl.oatuh2.service.UserTokenService;
//import org.springframework.security.oauth2.common.OAuth2AccessToken;
//import org.springframework.stereotype.Service;
//import org.springframework.web.HttpRequestMethodNotSupportedException;
//
//import java.security.Principal;
//import java.util.Map;
//
//@Service
//public class UserTokenServiceImpl implements UserTokenService {
//
//
//
//    @Override
//    public OAuth2AccessToken getUserToken(Principal principal,Map<String,String> params) throws HttpRequestMethodNotSupportedException {
////        try {
////            OAuth2AccessToken oAuth2AccessToken = tokenEndpoint.postAccessToken(principal,params).getBody();
////            return oAuth2AccessToken;
////        }catch (Exception e){
////            System.out.println(e);
////        }
//        return null;
//    }
//
//    @Override
//    public OAuth2AccessToken getMobileToken() {
//        return null;
//    }
//}
