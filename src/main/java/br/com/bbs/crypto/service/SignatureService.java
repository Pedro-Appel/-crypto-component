package br.com.bbs.crypto.service;

import javax.management.InvalidApplicationException;

public interface SignatureService extends ECCKeysService {
    public String sign(String privateKey, String message);

    public boolean verify(String publicKey, String message, String signature) throws InvalidApplicationException;
}
