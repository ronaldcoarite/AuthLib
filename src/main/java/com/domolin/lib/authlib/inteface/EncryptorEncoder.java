package com.domolin.lib.authlib.inteface;

/**
 *
 * @author Ronald
 * @param <T>
 */
public interface EncryptorEncoder<T> {
    public String getTextToEncrypt(T data);
    public T parse(String textEncrypted);
}
