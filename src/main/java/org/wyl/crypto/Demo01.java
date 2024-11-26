package org.wyl.crypto;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

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
public class Demo01 {


    public static void main(String[] args) throws Exception {
        String md51 = md51(); // ZajifYh5KDgxtmS9i38K1A==
        String md52 = md52(); // 65a8e27d8879283831b664bd8b7f0ad4
        String md53 = md53();
        String sha2561 = sha2561(); // 3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=
        String sha2562 = sha2562(); // dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    }

    public static String md51() throws Exception {
        String message = "Hello, World!";

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    public static String md52() throws Exception {
        String message = "Hello, World!";

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
        // 将处理后的字节转成 16 进制，得到最终 32 个字符
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        String signature = sb.toString();
        System.out.println(signature);
        return signature;
    }

    public static String md53() throws Exception {
        String message = "Hello, World!";

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
        // 将处理后的字节转成 16 进制，得到最终 32 个字符
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        String signature = sb.toString();
        System.out.println(signature);
        return signature;
    }

    public static String sha2561() throws Exception {
        String message = "Hello, World!";
        // 获取SHA-256的MessageDigest实例
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        // 计算哈希值
        byte[] hash = sha256Digest.digest(message.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    public static String sha2562() throws Exception {
        String message = "Hello, World!";
        // 获取SHA-256的MessageDigest实例
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        // 计算哈希值
        byte[] hash = sha256Digest.digest(message.getBytes(StandardCharsets.UTF_8));
        //  将字节数组转换为十六进制字符串表示
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        String signature = sb.toString();
        System.out.println(signature);
        return signature;
    }
}
