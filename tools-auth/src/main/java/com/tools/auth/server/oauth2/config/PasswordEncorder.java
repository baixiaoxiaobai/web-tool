package com.tools.auth.server.oauth2.config;//package com.open.capacity.server.oauth2.config;
//
//import java.util.regex.Pattern;
//
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.DisabledException;
//import org.springframework.security.crypto.bcrypt.BCrypt;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import com.open.capacity.utils.encrypt.AESUtil;
//
//import lombok.extern.slf4j.Slf4j;
///**
// * 
//* @ClassName: 	PasswordEncorder.java
//* @Description:	重写PasswordEncoder类，密码加密方法、AES加密，跟web端密码统一
//*  装配密码匹配器
//* @date: 		2019年5月13日
// */
//@Slf4j
//@Component
//public class PasswordEncorder implements PasswordEncoder{
//	
//	@Override
//    public String encode(CharSequence charSequence) {
//        log.info("============ charSequence.toString()  ============== " + charSequence.toString());
//        return AESUtil.AESEncrypt(charSequence.toString());
//    }
//
//    @Override
//    public boolean matches(CharSequence charSequence, String password) {
//        String pwd = charSequence.toString();
//        log.info("前端传过来密码为： " + pwd);
//        log.info("加密后密码为： " + AESUtil.AESEncrypt(pwd));
//        log.info("数据库密码为： " + password);
//        //password 应在数据库中加密
//        if( AESUtil.AESEncrypt(charSequence.toString()).equals(password)){
//            return true;
//        }
//        throw new DisabledException("--密码错误--");
//    }
//    
//   
//	private Pattern BCRYPT_PATTERN = Pattern
//			.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");
//	private final Log logger = LogFactory.getLog(getClass());
//	
//	public boolean bCryptPasswordEncoder(String rawPassword, String encodedPassword) {
//		if (encodedPassword == null || encodedPassword.length() == 0) {
//			logger.warn("Empty encoded password");
//			return false;
//		}
//
//		if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
//			logger.warn("Encoded password does not look like BCrypt");
//			return false;
//		}
//
//		return BCrypt.checkpw(rawPassword, encodedPassword);
//	}
//}
