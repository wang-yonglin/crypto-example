package com.fcbox.wash.factory.platform.biz;


import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSADemo03 {

    // RSA 密钥长度（字节）
    private static final int KEY_SIZE = 2048;
    // 加密块最大长度 = 密钥长度/8 - 填充长度（PKCS1Padding 占用 11 字节）
    private static final int MAX_ENCRYPT_BLOCK = KEY_SIZE / 8 - 2 * 32 - 2;
    // 解密块最大长度 = 密钥长度/8
    private static final int MAX_DECRYPT_BLOCK = KEY_SIZE / 8;

    public static void main(String[] args) throws Exception {
        // 1. 生成 RSA 密钥对
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 4. 转换为 Base64 编码方便展示或存储
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        System.out.println("RSA公钥:" + publicKeyBase64);
        System.out.println("RSA私钥:" + privateKeyBase64);

        // 待加密的原始数据（可能很长）
        String originalText = generateHugeData();
        System.out.println("原始数据: " + originalText);

        // 2. 使用公钥加密
        byte[] encryptedData = encrypt(originalText.getBytes(), publicKey);
        System.out.println("加密数据: " + Base64.getEncoder().encodeToString(encryptedData));

        // 3. 使用私钥解密
        byte[] decryptedData = decrypt(encryptedData, privateKey);
        String decryptedText = new String(decryptedData);
        System.out.println("解密数据: " + decryptedText);
    }

    /**
     * 公钥加密（支持分块处理长数据）
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        int inputLen = data.length;
        int offset = 0;
        int blockIndex = 0;
        byte[] cache;
        // 使用输出流收集分块结果
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            blockIndex++;
            offset = blockIndex * MAX_ENCRYPT_BLOCK;
        }
        return out.toByteArray();
    }

    /**
     * 私钥解密（支持分块处理长数据）
     */
    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        int inputLen = encryptedData.length;
        int offset = 0;
        int blockIndex = 0;
        byte[] cache;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            blockIndex++;
            offset = blockIndex * MAX_DECRYPT_BLOCK;
        }
        return out.toByteArray();
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