package com.domolin.lib.authlib.util;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class SignatureUtil {

    public static void main(String cor[]) throws Exception {
        SignatureUtil signatureUtil = new SignatureUtil();
        File filePublic = new File("D:\\apps\\seguridad\\claves\\public.pem");
        PublicKey publicKey = signatureUtil.readPublicKey(filePublic);

        File filePrivate = new File("D:\\apps\\seguridad\\claves\\private2.pem");
        PrivateKey privateKey = signatureUtil.readPriateKey(filePrivate);
    }

    public static boolean verify(PublicKey publicKey, String header, String payload, String signature) {
        try {
            String data = header + "." + payload;
            Signature sig = Signature.getInstance(Firma.ALGORITMO_FIRMA);
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            byte[] decodedSignature = Base64.getUrlDecoder().decode(signature);
            return sig.verify(decodedSignature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String sign(PrivateKey privateKey, byte[] payload) throws Exception {
        Signature privateSignature = Signature.getInstance(Firma.ALGORITMO_FIRMA);
        privateSignature.initSign(privateKey);
        privateSignature.update(payload);

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(Firma.ALGORITMO_FIRMA);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static PrivateKey readPriateKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());

        String temp = new String(keyBytes);
        String privKeyPEM = temp.replaceAll("[\n|\r]", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        byte[] decoded = Base64.getDecoder().decode(privKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(Firma.METODO_FIRMA);
        return kf.generatePrivate(spec);
    }

    public static PublicKey readPublicKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replaceAll("[\n|\r]", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance(Firma.METODO_FIRMA);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return kf.generatePublic(spec);
    }

    public static String decrypt(String toDecode, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(toDecode));
        return new String(bytes);
    }

    public static String encrypt(String toEncode,PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(toEncode.getBytes(StandardCharsets.UTF_8));
        byte[] encoded = Base64.getEncoder().encode(bytes);
        return new String(encoded);
    }
}
