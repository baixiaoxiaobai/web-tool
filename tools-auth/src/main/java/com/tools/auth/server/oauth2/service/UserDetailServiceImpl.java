//package com.tools.auth.server.oauth2.service;
//
//import com.open.capacity.model.system.LoginAppUser;
//import com.open.capacity.server.oauth2.feign.UserClient;
//import com.open.capacity.server.oauth2.feign.UserLoginGrpc;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
//import org.springframework.security.authentication.DisabledException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
///**
//* @ClassName: 	UserDetailServiceImpl.java
//* @Description: 该类的功能描述：spring security 自定义用户验证逻辑，取sys_user表
//* /oauth/token  默认方法UserDetailsService重写loadUserByUsername获取用户信息
//* @date: 		2019年5月6日
// */
//@Slf4j
//@Service
//public class UserDetailServiceImpl implements UserDetailsService {
//
//    @Autowired
//    private UserClient userClient;
//
//    @Autowired
//    private UserLoginGrpc userLoginGrpc;
//
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//    	//方式1  feign调用       对外feign resttemplate
//    	LoginAppUser loginAppUser = new LoginAppUser();
//        loginAppUser = userClient.findByUsername(username);
//        if(loginAppUser==null) {
//        	loginAppUser = userClient.findUserByMobile(username);
//        }
//        System.out.println("获取登录用户信息===================");
////        //方式2  gprc调用		对内grpc dubbo
////        LoginAppUser loginAppUser = userLoginGrpc.findByUsername(username);
//        if (loginAppUser == null) {
//            throw new AuthenticationCredentialsNotFoundException("用户不存在");
//        } else if (!loginAppUser.isEnabled()) {
//            throw new DisabledException("用户已作废");
//        }
//
//        return loginAppUser;
//    }
//
//
//
//}
