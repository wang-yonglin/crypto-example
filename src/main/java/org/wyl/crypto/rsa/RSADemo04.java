package org.wyl.crypto.rsa;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class RSADemo04 {

    // RSA 密钥生成（同上）
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    // 生成 AES 密钥（256位）
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // RSA 加密 AES 密钥
    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey rsaPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    // RSA 解密得到 AES 密钥
    public static SecretKey decryptAESKey(byte[] encryptedKey, PrivateKey rsaPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] keyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // AES-GCM 加密数据（带认证）
    public static byte[] encryptData(byte[] plainData, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV(); // GCM 自动生成随机 IV
        byte[] cipherText = cipher.doFinal(plainData);
        // 将 IV 拼接在密文前，便于解密
        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
        return result;
    }

    // AES-GCM 解密数据
    public static byte[] decryptData(byte[] encryptedData, SecretKey aesKey) throws Exception {
        // 前12字节是GCM IV（96位）
        byte[] iv = new byte[12];
        System.arraycopy(encryptedData, 0, iv, 0, 12);
        byte[] cipherText = new byte[encryptedData.length - 12];
        System.arraycopy(encryptedData, 12, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        return cipher.doFinal(cipherText);
    }

    // 演示完整流程
    public static void main(String[] args) throws Exception {
        // 接收方的 RSA 密钥对（实际场景中公钥是对方的）
        KeyPair rsaKeyPair = generateRSAKeyPair();
        PublicKey rsaPub = rsaKeyPair.getPublic();
        PrivateKey rsaPriv = rsaKeyPair.getPrivate();
        System.out.println("公钥: " + Base64.getEncoder().encodeToString(rsaPub.getEncoded()));
        System.out.println("私钥: " + Base64.getEncoder().encodeToString(rsaPriv.getEncoded()));


        // 发送方：生成随机 AES 密钥
        SecretKey aesKey = generateAESKey();
        System.out.println("AES密钥原文: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // 2. 用 RSA 公钥加密 AES 密钥（可以安全传输）
        byte[] encryptedAesKey = encryptAESKey(aesKey, rsaPub);
        System.out.println("AES密钥密文: " + Base64.getEncoder().encodeToString(encryptedAesKey));

        // 3. 用 AES 加密真正的大数据（任意长度）
        String hugeData = generateHugeData();
        byte[] plainData = hugeData.getBytes("UTF-8");
        byte[] encryptedData = encryptData(plainData, aesKey);
        System.out.println("加密内容原文: " + hugeData);
        System.out.println("加密内容密文: " + Base64.getEncoder().encodeToString(encryptedData));

        // === 传输：encryptedAesKey + encryptedData ===

        // 4. 接收方：用 RSA 私钥解密得到 AES 密钥
        SecretKey recoveredAesKey = decryptAESKey(encryptedAesKey, rsaPriv);
        System.out.println("AES密钥解密: " + Base64.getEncoder().encodeToString(recoveredAesKey.getEncoded()));

        // 5. 用 AES 密钥解密数据
        byte[] decryptedData = decryptData(encryptedData, recoveredAesKey);
        String recoveredText = new String(decryptedData, "UTF-8");
        System.out.println("加密内容解密: " + recoveredText);

        System.out.println("解密成功，数据匹配：" + hugeData.equals(recoveredText));
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