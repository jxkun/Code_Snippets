package test.urlcode;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class EncryptionUtil {
	/**
	 *  MD5消息签名  
	 * 	byte转换为String采用的为byte2String
	 * @param content
	 * @return
	 */
	public static String md5(String content){
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] bytes = md.digest(content.getBytes());
			//String byte2hex = byte2hex(bytes);
			String byte2String = byte2HexString(bytes);
			return byte2String;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.out.println("MD5加密失败");
		}
		return null;
	}
	
	/**
	 * SHA1 消息摘要
	 * @param content
	 * @return
	 * @throws Exception
	 */
	public static String sha1(String content) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] digest = sha1.digest(content.getBytes("utf-8"));
		return byte2HexString(digest);
		
	}
	
	/**
	 * base64加密
	 * @param bytes
	 * @return
	 */
	public static String byte2base64(byte[] bytes) {
		BASE64Encoder base64Encoder = new BASE64Encoder();
		return base64Encoder.encode(bytes);
	}
	
	/**
	 * base64解密
	 * @param base64
	 * @return
	 * @throws IOException
	 */
	public static byte[] base642byte(String base64) throws IOException {
		BASE64Decoder base64Decoder = new BASE64Decoder();
		return base64Decoder.decodeBuffer(base64);
	}
	
	/**
	 *  将byte数组转换成16进制字符串  
	 *  若byte为负数，则转换成对应的int型整数大小
	 * @param bytes
	 * @return
	 */
	public static String byte2hex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for(byte by : bytes) {
			int inte = Math.abs(by);
			if(by < 0) {
				inte = inte | 0x80; // 为负数则将byte的第8位置为1
			}
			String hexString = Integer.toHexString(inte & 0xff); //截取一个byte长度
			if(hexString.length() == 1) {
				sb.append("0");
			}
			sb.append(hexString.toLowerCase());
		}
		return sb.toString();
	}
	
	/**
	 * 将16进制字符串转换成byte数组, 与上面的 byte2hex相对应
	 * @param hex
	 * @return
	 */
	public static byte[] hex2byte(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for(int i = 0; i < hex.length(); i += 2) {
			String subStr = hex.substring(i, i + 2);
			boolean negtive = false; // 判断是否为负数
			int inte = Integer.parseInt(subStr, 16);
			if(inte > 127)  negtive = true;
			if(inte == 128) {
				inte = -128;
			}else if(negtive){
				inte = 0 - (inte & 0x7f); //为负数，则通过 & 0x7f获取其为整数时的大小， 然后转换为对应负数
			}
			bytes[i/2] = (byte) inte;
		}
		
		return bytes;
	}
	
	/**
	 * 将byte数组,转换成16进制字符串
	 * @param bytes
	 * @return
	 */
	public static String byte2HexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < bytes.length; i ++) {
			String hexString = Integer.toHexString(bytes[i] & 0xff);
			if(hexString.length() == 1) {
				sb.append("0");
			}
			sb.append(hexString);
		}
		return sb.toString();
	}
	
	/**
	 * 将16进制字符串转换成byte数组
	 * @param hex
	 * @return
	 */
	public static byte[] hexString2byte(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for(int i = 0; i < hex.length(); i += 2) {
			String subStr = hex.substring(i, i+2);
			int parseInt = Integer.parseInt(subStr, 16);
			bytes[i/2] =(byte) (parseInt & 0xff);
		}
		return bytes;
	}
	
	/** ==========================DES加密算法================================ 
	 * DES属于对称加密算法， 明文按照64位进行分组， 秘钥长度64位， 但实际只有56位参与DES运算
	 * (第8、16、24、32、40、48、56、64位是校验位， 使得每个秘钥都有奇数个1)
	 */
	
	/**
	 * 生成秘钥字符串
	 * @return
	 * @throws Exception
	 */
	public static String getKeyDES() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(56);
		SecretKey key = keyGen.generateKey();
		String base64str = byte2base64(key.getEncoded());
		return base64str;
	}
	
	/**
	 * 将秘钥字符串转换为SecretKey对象
	 * @param base64Key
	 * @return
	 * @throws Exception
	 */
	public static SecretKey loadKeyDES(String base64Key) throws Exception {
		byte[] bytes = base642byte(base64Key);
		SecretKey key = new SecretKeySpec(bytes, "DES");
		return key;
	}
	
	/**
	 * 对source进行加密， 返回加密后的byte数组
	 * @param source 需要加密的bytes数组
	 * @param key 秘钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptDES(byte[] source, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		return bytes;
	}
	/**
	 * 将source解密， 返回解密后的byte数组
	 * @param source 需要解密的byte数组
	 * @param key 秘钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptDES(byte[] source, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		return bytes;
	}
	
	/**===========================AES加密=====================================
	 * AES 高级加密标准， 秘钥长度可以为128、192、256位
	 * 常用的秘钥长度为128位
	 * */
	
	/**
	 * 生成AES秘钥, base64格式字符串
	 * @return
	 * @throws Exception 
	 */
	public static String getKeyAES() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();
		String base64str = byte2base64(key.getEncoded());
		return base64str;
	}
	
	/**
	 * 将base64格式AES秘钥字符串解析为SecretKey
	 * @param base64Key
	 * @return
	 * @throws Exception
	 */
	public static SecretKey loadKeyAES(String base64Key) throws Exception {
		byte[] bytes = base642byte(base64Key);
		SecretKey key = new SecretKeySpec(bytes, "AES");
		return key;
	}
	
	/**
	 * 对source进行加密， 返回加密后的byte数组
	 * @param source
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptAES(byte[] source, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		return bytes;
	}
	
	/**
	 * 将source使用AES秘钥进行解密
	 * @param source
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] source, SecretKey key) throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		return bytes;
	}
	
	/**========================= 非对称加密 RSA ==============================
	 * RSA 基于大素数相乘的结果难以质因数分解的困难数学问题
	 */
	
	/**
	 * 初始化KeyPairGenerator， 通过KeyPairGenerator获取KeyPair，
	 * 由KeyPair可以获取RSA公私钥对
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKeyPair() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	/**
	 * 生成RSA公钥
	 * @param keyPair
	 * @return
	 */
	public static String getPublicKey(KeyPair keyPair) {
		PublicKey publicKey = keyPair.getPublic();
		byte[] bytes = publicKey.getEncoded();
		return byte2base64(bytes);
	}

	/**
	 * 生成RSA私钥
	 * @param keyPair
	 * @return
	 */
	public static String getPrivateKey(KeyPair keyPair) {
		PrivateKey privateKey = keyPair.getPrivate();
		byte[] bytes = privateKey.getEncoded();
		return byte2base64(bytes);
	}
	
	/**
	 * 将base64转码的RSA公钥字符串转换成PublicKey对象
	 * @param publicStr
	 * @return
	 * @throws Exception
	 */
	public static PublicKey string2PublicKey(String publicStr) throws Exception {
		byte[] keyBytes = base642byte(publicStr);
		
		/**
		 * This class represents the ASN.1 encoding of a public key,
		 * encoding according to the ASN.1 type
		 */
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	/**
	 * 将base64转码的RSA私钥字符串转换成PrivateKey对象
	 * @param priStr
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey string2PrivateKey(String priStr) throws Exception {
		byte[] keyBytes = base642byte(priStr);
		
		/**
		 * This class represents the ASN.1 encoding of a public key,
		 * encoding according to the ASN.1 type
		 */
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}
	
	/**
	 * 使用RSA公钥加密
	 * @param content
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytes = cipher.doFinal(content);
		return bytes;
	}
	
	/**
	 * 使用RSA私钥解密
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytes = cipher.doFinal(content);
		return bytes;
	}
	
	/** ================================ 数字签名 =====================================
	 * 签名认证是对非对称加密技术与数字摘要技术的综合运用， 指将通信内容的摘要信息使用发送者的私钥进行加密， 然后将密文与原文一起传输给信息的接受者。
	 * 主要是为了验证数据的完整性， 数据一旦被人修改，可以立即得知。
	 * 常见的数字签名算法包括： MD5withRSA SHA1withRSA
	 */
	
	/**
	 * 将content明文生成数字签名
	 * @param content
	 * @param privateKey
	 * @param type 数字摘要类型， MD5 或者 SHA1
	 * @return
	 * @throws Exception 
	 */
	public static byte[] sign(byte[] content, PrivateKey privateKey, String type) throws Exception {
		MessageDigest md = MessageDigest.getInstance(type);
		byte[] bytes = md.digest(content);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] encryBytes = cipher.doFinal(bytes);
		return encryBytes;
	}
	
	/**
	 * 将数字签名解密， 将明文生成数字摘要， 比对是否相等， 可以得出数据是否被篡改
	 * @param content
	 * @param sign
	 * @param publicKey
	 * @param type 数字摘要类型， MD5 或者 SHA1
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] content, byte[] sign, PublicKey publicKey, String type) {
		try {
			MessageDigest md = MessageDigest.getInstance(type);
			byte[] bytes = md.digest(content);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			byte[] decryptBytes = cipher.doFinal(sign);
			if(byte2base64(bytes).equals(byte2base64(decryptBytes))) {
				return true;
			}else {
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	/**===================== 基于Signature API 进行数字签名 ===========================
	 */
	/**
	 * 基于Signature API 进行数字签名
	 * @param content
	 * @param privateKey
	 * @param type 数字签名， 例如 MD5withRSA、SHA1withRSA 
	 * @return
	 * @throws Exception 
	 */
	public static byte[] sign2(byte[] content, PrivateKey privateKey, String type) throws Exception {
		Signature signature = Signature.getInstance(type);
		signature.initSign(privateKey);
		signature.update(content);
		return signature.sign();
	}
	
	/**
	 * 基于Signature API 进行数据完整性校验
	 * @param content
	 * @param sign
	 * @param publicKey
	 * @param type 数字签名， 例如 MD5withRSA、SHA1withRSA 
	 * @return
	 */
	public static boolean verify2(byte[] content, byte[] sign, PublicKey publicKey, String type) {
		try {
			Signature signature = Signature.getInstance(type);
			signature.initVerify(publicKey);
			signature.update(content);
			return signature.verify(sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
}
