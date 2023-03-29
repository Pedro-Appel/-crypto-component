package br.com.bbs.crypto.service;

import br.com.bbs.crypto.model.dto.KeyPairDTO;

import javax.management.InvalidApplicationException;
import java.rmi.ServerException;

public interface ECCKeysService {
    public KeyPairDTO generateKeyPair() throws InvalidApplicationException, ServerException;
}
