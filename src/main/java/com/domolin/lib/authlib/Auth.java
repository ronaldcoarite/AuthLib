package com.domolin.lib.authlib;

import com.domolin.lib.authlib.dto.PayloadAuth;
import com.domolin.lib.authlib.encoder.AccessEnconder;
import com.domolin.lib.authlib.error.SecurityKeyException;
import com.domolin.lib.authlib.inteface.EncryptorEncoder;
import com.domolin.lib.authlib.util.Firma;
import com.domolin.lib.authlib.util.SignatureUtil;
import java.io.File;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


// ENCRIPTACION 
// https://gustavopeiretti.com/rsa-encrypt-decrypt-java/

public class Auth<T> {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private EncryptorEncoder<T> encryptorEncoder;

    public void loadPrimaryKey(String pathKey){
        try {
            privateKey = SignatureUtil.readPriateKey(new File(pathKey));
        } catch (Exception e) {
            throw new RuntimeException("No se encuentra la clave pública en la ruta [" + pathKey + "]");
        }
    }
    
    public void loadPublicKey(String pathKey){
        try {
            publicKey = SignatureUtil.readPublicKey(new File(pathKey));
        } catch (Exception e) {
            throw new RuntimeException("No se encuentra la clave pública en la ruta [" + pathKey + "]");
        }
    }

    public void setEncryptorEncoder(EncryptorEncoder encryptorEncoder) {
        this.encryptorEncoder = encryptorEncoder;
    }
    
    public String generateSecurityKey(T payloadAut) throws SecurityKeyException{
        String text = encryptorEncoder.getTextToEncrypt(payloadAut);
        try {
            String txtEncripted = SignatureUtil.encrypt(text, publicKey);
            return txtEncripted;
        } catch (Exception e) {
            throw new SecurityKeyException("Error al generar el Token para la Autorización", e);
        }
    }
    
    public T decodeSecurityKey(String token)throws SecurityKeyException{
        try {
            String text = SignatureUtil.decrypt(token, privateKey);
            T data = encryptorEncoder.parse(text);
            return data;
        } catch (Exception e) {
            throw new SecurityKeyException("Error al decodificar el Token para la Autorización", e);
        }
    }
    
    public static void main(String cor[]) throws Exception{
        Auth<PayloadAuth> auth = new Auth();
        auth.loadPrimaryKey("D:\\proyects\\iot_server\\IotSecurity\\claves\\private2.pem");
        auth.loadPublicKey("D:\\proyects\\iot_server\\IotSecurity\\claves\\public.pem");
        PayloadAuth payloadAuth = new PayloadAuth();
        payloadAuth.setUserId("21345678");
        payloadAuth.setRols(new String[]{"ROL_A1","ROL_2"});
        
        AccessEnconder accessEnconder = new AccessEnconder();
        auth.setEncryptorEncoder(accessEnconder);
        
        String token = auth.generateSecurityKey(payloadAuth);
        System.out.println("TOKEN");
        System.out.println(token);
        
        PayloadAuth ayAuth = auth.decodeSecurityKey(token);
        System.out.println("DECODIFICADO");
        System.out.println(ayAuth);
    }

    private boolean verify(byte[] textBytes, String signature, PublicKey publicKey) 
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(Firma.ALGORITMO_FIRMA);
        publicSignature.initVerify(publicKey);
        publicSignature.update(textBytes);

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    private PublicKey readPublicKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replaceAll("[\n|\r]", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance(Firma.METODO_FIRMA);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return kf.generatePublic(spec);
    }
}
