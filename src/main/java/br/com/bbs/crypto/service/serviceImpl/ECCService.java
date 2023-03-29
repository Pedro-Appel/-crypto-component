package br.com.bbs.crypto.service.serviceImpl;

import br.com.bbs.crypto.model.dto.KeyPairDTO;
import br.com.bbs.crypto.service.CryptographyService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.InvalidApplicationException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class ECCService implements CryptographyService {

    public static final String ALGORITHM = "EC";
    public static final String PARAMETER_SPEC = "secp256r1";
    public static final String CIPHER_INSTANCE = "ECIES/None/NoPadding";
    public static final String PROVIDER = "BC";
    public static final int HEX_DECIMAL = 16;

    public ECCService() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeys() throws InvalidApplicationException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            SecureRandom sRandom = SecureRandom.getInstanceStrong();
            ECGenParameterSpec ecParams = new ECGenParameterSpec(PARAMETER_SPEC);
            keyPairGenerator.initialize(ecParams, sRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new InvalidApplicationException(e);
        }
    }

    @Override
    public String encrypt(String publicKey, String plainText) throws InvalidApplicationException {

        byte[] pubKey = Base64.decode(publicKey);

        X509EncodedKeySpec specPublic = new X509EncodedKeySpec(pubKey);
        try {

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey instanceOfPublicKey = keyFactory.generatePublic(specPublic);
            Cipher enCipher = Cipher.getInstance(CIPHER_INSTANCE);
            enCipher.init(Cipher.ENCRYPT_MODE, instanceOfPublicKey);

            byte[] ciphertext = enCipher.doFinal(plainText.getBytes());

            return new BigInteger(1, ciphertext).toString(HEX_DECIMAL);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidApplicationException(e);
        }
    }

    public String decrypt(String privateKey, String cipherText) throws InvalidApplicationException {

        byte[] pubKeyBytes = Base64.decode(privateKey);
        try {
            KeySpec keySpec = new PKCS8EncodedKeySpec(pubKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            PrivateKey instanceOfPrivateKey = keyFactory.generatePrivate(keySpec);
            Cipher deCipher = Cipher.getInstance(CIPHER_INSTANCE, PROVIDER);
            deCipher.init(Cipher.DECRYPT_MODE, instanceOfPrivateKey);

            byte[] plainText = deCipher.doFinal(new BigInteger(cipherText, HEX_DECIMAL).toByteArray());

            return new String(plainText);

        } catch (Exception e) {
            throw new InvalidApplicationException(e);
        }
    }

    public KeyPairDTO generateKeyPair() throws InvalidApplicationException {
        return new KeyPairDTO(generateKeys());
    }
}
