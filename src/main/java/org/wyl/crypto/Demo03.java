package org.wyl.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @Title: Demo01.java
 * @Package org.wyl.crypto
 * @Description: (用一句话描述该文件做什么)
 * @Author: 005617
 * @Date: 2024/11/26 13:50
 * @Version V1.0
 * @License: Copyright Since 2015 Hive Box Technology. All rights reserved.
 * @Notice: This content is limited to the internal circulation of Hive Box, and it is prohibited to leak or used for other commercial purposes.
 */
public class Demo03 {

    public static void main(String[] args) throws Exception {
        // 待加密内容
        String str = "123456";
        // 密码，长度要是8的倍数 密钥随意定
        String password = "12345678";
        byte[] encrypt = encrypt(str.getBytes(), password);
        String encryptStr =  Base64.getEncoder().encodeToString(encrypt);
        System.out.println("加密前:" + str);
        System.out.println("加密后:" + encryptStr);
        // 解密
        byte[] encryptArr = Base64.getDecoder().decode(encryptStr);
        byte[] decrypt = decrypt(encryptArr, password);

        System.out.println("解密后:" + new String(decrypt));
    }


    public static byte[] encrypt(byte[] datasource, String password) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(password.getBytes());
            // 创建一个密匙工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密匙初始化Cipher对象,ENCRYPT_MODE用于将 Cipher 初始化为加密模式的常量
            cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
            // 现在，获取数据并加密
            // 正式执行加密操作
            return cipher.doFinal(datasource); // 按单部分操作加密或解密数据，或者结束一个多部分操作
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }


    public static byte[] decrypt(byte[] src, String password) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom random = new SecureRandom();
        // 创建一个DESKeySpec对象
        DESKeySpec desKey = new DESKeySpec(password.getBytes());
        // 创建一个密匙工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");// 返回实现指定转换的
        // Cipher
        // 对象
        // 将DESKeySpec对象转换成SecretKey对象
        SecretKey securekey = keyFactory.generateSecret(desKey);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance("DES");
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, random);
        // 真正开始解密操作
        return cipher.doFinal(src);
    }
}
