package test.urlcode;

import java.io.IOException;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.junit.Test;

public class EncryptionUtilTest {
	
	private final String testStr = "测试数据"; 
	
	@Test
	public void testMD5() {
		String md5 = EncryptionUtil.md5(testStr);
		System.out.println("MD5-加密： " + md5 + " 长度： " + md5.length());
	}

	@Test
	public void testByte2base64() {
		String byte2base64 = EncryptionUtil.byte2base64(testStr.getBytes());
		System.out.println("byte2base64: " + byte2base64);
	}

	@Test
	public void testBase642byte() throws IOException {
		byte[] base642byte = EncryptionUtil.base642byte(EncryptionUtil.byte2base64(testStr.getBytes()));
		String string = new String(base642byte);
		System.out.println("base642byte: " + string);
	}

	@Test
	public void testSHA1() throws Exception {
		String sha1 = EncryptionUtil.sha1(testStr);
		System.out.println("SHA1: " + sha1 + " 长度： " + sha1.length());
	}
	
	@Test
	public void testEncryptDES() throws Exception {
		String keyDES = EncryptionUtil.getKeyDES();
		SecretKey key = EncryptionUtil.loadKeyDES(keyDES);
		byte[] encryptDES = EncryptionUtil.encryptDES("hellohello1234567891115646846165".getBytes("utf-8"), key);
		System.out.println(EncryptionUtil.byte2HexString(encryptDES));
		byte[] decryptDES = EncryptionUtil.decryptDES(encryptDES, key);
		System.out.println(new String(decryptDES));
	}
	
	@Test
	public void hexString2byte() throws Exception {
		String byte2HexString = EncryptionUtil.byte2HexString("hello".getBytes());
		System.out.println(byte2HexString);
		byte[] bs = EncryptionUtil.hexString2byte(byte2HexString);
		System.out.println(new String(bs));
		
		int i = -110;
		byte tmp = (byte)(i & 0xff);
		System.out.println(tmp);
	}
	
	@Test
	public void testAES() throws Exception{
		String keyAES = EncryptionUtil.getKeyAES();
		System.out.println(keyAES);
		SecretKey key = EncryptionUtil.loadKeyAES(keyAES);
		String str = "滑稽12346579846553c测试字符串";
		byte[] bs = EncryptionUtil.encryptAES(str.getBytes(), key);
		System.out.println(EncryptionUtil.byte2base64(bs));
		
		byte[] decrypt = EncryptionUtil.decrypt(bs, key);
		System.out.println(new String(decrypt));
	}
	
	@Test
	public void testRSA() throws Exception{
		KeyPair keyPair = EncryptionUtil.getKeyPair();
		String publicKey = EncryptionUtil.getPublicKey(keyPair);
		System.out.println("publicKey: " + publicKey);
		String privateKey = EncryptionUtil.getPrivateKey(keyPair);
		System.out.println("privateKey: " + privateKey);
		
		String str = "what are 有  doing ？？？？ hehe  伙计";
		byte[] bs = EncryptionUtil.publicEncrypt(str.getBytes(), EncryptionUtil.string2PublicKey(publicKey));
		System.out.println("公钥加密后: " + EncryptionUtil.byte2base64(bs));
		
		byte[] bs2 = EncryptionUtil.privateDecrypt(bs, EncryptionUtil.string2PrivateKey(privateKey));
		System.out.println("明文： " + new String(bs2));
	}

	@Test
	public void testMD5whithRSA() throws Exception{
		String str = "what are 有  doing ？？？？ hehe  伙计";
		KeyPair keyPair = EncryptionUtil.getKeyPair();
		byte[] sign = EncryptionUtil.sign(str.getBytes(),keyPair.getPrivate() , "md5");
		System.out.println(EncryptionUtil.byte2base64(sign));
		System.out.println(sign[0]=2);
		System.out.println(EncryptionUtil.verify(str.getBytes(), sign, keyPair.getPublic(), "md5"));
	}

	@Test
	public void testSHA1whithRSA() throws Exception{
		String str = "what are 有  doing ？？？？ hehe  伙计";
		KeyPair keyPair = EncryptionUtil.getKeyPair();
		byte[] sign = EncryptionUtil.sign(str.getBytes(),keyPair.getPrivate() , "SHA1");
		System.out.println(EncryptionUtil.byte2base64(sign));
		System.out.println(sign[0]);
		System.out.println(EncryptionUtil.verify(str.getBytes(), sign, keyPair.getPublic(), "SHA1"));
	}
	
	@Test
	public void testSignature() throws Exception{
		String str = "what are 有  doing ？？？？ hehe  伙计";
		KeyPair keyPair = EncryptionUtil.getKeyPair();
		byte[] sign = EncryptionUtil.sign2(str.getBytes(),keyPair.getPrivate() , "SHA1withRSA");
		System.out.println(EncryptionUtil.byte2base64(sign));
		System.out.println(sign[0]);
		System.out.println(EncryptionUtil.verify2(str.getBytes(), sign, keyPair.getPublic(), "SHA1withRSA"));
	}
	
}
