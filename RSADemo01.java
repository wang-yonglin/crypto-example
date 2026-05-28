package com.fcbox.wash.factory.platform.biz;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSADemo01 {

    // 生成 RSA 密钥对（2048位）
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // 从 Base64 字符串恢复公钥
    public static PublicKey getPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // 从 Base64 字符串恢复私钥
    public static PrivateKey getPrivateKey(String base64PrivateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // 公钥加密
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 私钥解密
    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, "UTF-8");
    }

    // 私钥签名
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plainText.getBytes("UTF-8"));
        byte[] signBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signBytes);
    }

    // 公钥验签
    public static boolean verify(String plainText, String signatureText, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(plainText.getBytes("UTF-8"));
        byte[] signBytes = Base64.getDecoder().decode(signatureText);
        return signature.verify(signBytes);
    }

    // 测试主方法
    public static void main(String[] args) throws Exception {
        // 1. 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 2. 将密钥转为 Base64 字符串（便于存储/传输）
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        System.out.println("公钥: " + publicKeyBase64);
        System.out.println("私钥: " + privateKeyBase64);

        // 3. 模拟公钥加密、私钥解密
        String original = generateHugeData();
        String encrypted = encrypt(original, publicKey);
        String decrypted = decrypt(encrypted, privateKey);

        System.out.println("原文: " + original);
        System.out.println("密文: " + encrypted);
        System.out.println("解密: " + decrypted);

        // 4. 模拟私钥签名、公钥验签
        String signature = sign(original, privateKey);
        boolean isVerified = verify(original, signature, publicKey);

        System.out.println("签名: " + signature);
        System.out.println("验签结果: " + isVerified);
    }


    private static String generateHugeData() {
        String base = "这是一段非常长的数据，远超RSA-2048/OAEP加密上限190字节，因此必须使用RSA加密AES密钥、AES加密数据的混合加密方案。";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append(base);
        }
        return sb.toString();
    }
}