package com.domolin.lib.authlib.encoder;

import com.domolin.lib.authlib.dto.PayloadAuth;
import com.domolin.lib.authlib.inteface.EncryptorEncoder;

/**
 *
 * @author Ronald
 */
public class AccessEnconder implements EncryptorEncoder<PayloadAuth>{

    @Override
    public String getTextToEncrypt(PayloadAuth payloadAut) {
        String text = String.format(
                "%s#%s", 
                payloadAut.getUserId(),
                payloadAut.getRols()==null?"":String.join(",",payloadAut.getRols()));
        return text;
    }

    @Override
    public PayloadAuth parse(String textDecrypted) {
        String txts[] = textDecrypted.split("#", 2);
        PayloadAuth payloadAuth = new PayloadAuth();
        payloadAuth.setUserId(txts[0]);
        payloadAuth.setRols(txts[1].split(","));
        return payloadAuth;
    }
}
