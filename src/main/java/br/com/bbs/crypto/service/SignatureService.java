package br.com.bbs.crypto.service;

import br.com.bbs.crypto.exception.CipherException;
import br.com.bbs.crypto.exception.KeyParseException;

import javax.management.InvalidApplicationException;

public interface SignatureService extends ECCKeysService {
    public String sign(String privateKey, String message) throws KeyParseException, CipherException;

    public boolean verify(String publicKey, String message, String signature) throws InvalidApplicationException, KeyParseException, CipherException;
}
