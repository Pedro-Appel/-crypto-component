package br.com.bbs.crypto.model.dto;

import java.security.KeyPair;
import java.util.Base64;

public class KeyPairDTO {

    private String t1;
    private String t2;

    public KeyPairDTO(KeyPair keyPair) {
        this.t1 = Base64.getUrlEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        this.t2 = Base64.getUrlEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
    public static byte[] getPublicKeyDecoded(String publicKey) {
        return Base64.getUrlDecoder().decode(publicKey);
    }

    @Override
    public String toString() {
        return "KeyPairDTO{" +
                "t1='" + t1 + '\'' +
                ", t2='" + t2 + '\'' +
                '}';
    }

    public String getPublicKey() {
        return this.t2;
    }

    public String getPrivateKey() {
        return this.t1;
    }
}
