package br.com.bbs.crypto.service;

import javax.management.InvalidApplicationException;

public interface CryptographyService extends ECCKeysService{

    public String encrypt(String publicKey, String plainText) throws InvalidApplicationException;
    public String decrypt(String privateKey, String cipherText) throws InvalidApplicationException;
}
