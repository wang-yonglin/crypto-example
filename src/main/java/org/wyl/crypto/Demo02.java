package org.wyl.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

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
public class Demo02 {


    public static void main(String[] args) throws Exception {
        String hmacMD5 = hmacMD5(); // b5xtaKvu4JR0QugTTh6eXQ==
        String hmacSHA1 = hmacSHA1(); // ccqO6tBMk68JX5R21UyIO2EKbqQ=
        String hmacSHA224 = hmacSHA224(); // ZMnX5Z7IExq2iqlVA2VHejlJAeWBolSE3XxDDQ==
        String hmacSHA256 = hmacSHA256(); // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        String hmacSHA384 = hmacSHA384();  // UNu9ngFGLCVUdyrF/XOVSnJXASeZIR6EbWwEDhQ0kjKtnA2rLc+HVFPk/C9MnDzZ
        String hmacSHA512 = hmacSHA512(); // ymv9IFp3OaxfbhcK7dFtPohjF6SDgrqby8X1OId9B93M7WUQ/yN0U+tOCCHIaGJQQRc9wHJ8skt8BaKQdhjDZw==
//        String hmacSHA512AND224 = hmacSHA512AND224();
//        String hmacSHA512AND256 = hmacSHA512AND256();
    }

    private static String hmacMD5() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    private static String hmacSHA1() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    private static String hmacSHA224() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA224");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    private static String hmacSHA256() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    private static String hmacSHA384() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA384");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }

    private static String hmacSHA512() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA512");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }


    private static String hmacSHA512AND224() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA512/224");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }


    private static String hmacSHA512AND256() throws Exception {
        String message = "Hello, World!";
        String key = "secretkey";

        Mac mac = Mac.getInstance("HmacSHA512/256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm());
        mac.init(secretKey);
        // JiqJB8XpY4HxXeegdycgUPZuo0f8//TTRKE3zGyDUng=
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
//        String signature = Base64.getEncoder().encodeToString(hash);
        String signature = Base64.encodeBase64String(hash);
        System.out.println(signature);
        return signature;
    }
}
