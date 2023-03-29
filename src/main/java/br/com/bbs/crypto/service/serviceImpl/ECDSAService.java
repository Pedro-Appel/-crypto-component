package br.com.bbs.crypto.service.serviceImpl;

import br.com.bbs.crypto.exception.CipherException;
import br.com.bbs.crypto.exception.KeyParseException;
import br.com.bbs.crypto.model.dto.KeyPairDTO;
import br.com.bbs.crypto.service.SignatureService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.management.InvalidApplicationException;
import java.rmi.ServerException;
import java.security.*;
import java.security.spec.*;
public class ECDSAService implements SignatureService {

    public static final String ALGORITHM = "ECDSA";
    public static final String PROVIDER = "BC";
    public static final String PARAMETER_SPEC = "prime256v1";

    public ECDSAService() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeys() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            SecureRandom random = SecureRandom.getInstanceStrong();
            ECGenParameterSpec params = new ECGenParameterSpec(PARAMETER_SPEC);
            keyPairGenerator.initialize(params, random);
            return keyPairGenerator.generateKeyPair();

        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("Invalid Provider");
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }


    @Override
    public String sign(String privateKey, String message) throws KeyParseException, CipherException {

        PrivateKey instanceOfPrivateKey = null;

        try {
            byte[] pubKeyBytes = Base64.decode(privateKey);
            KeySpec keySpec = new PKCS8EncodedKeySpec(pubKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            instanceOfPrivateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyParseException("Failed to parse Key", e);
        }

        try {
            Signature signature = Signature.getInstance(ALGORITHM,PROVIDER);
            signature.initSign(instanceOfPrivateKey);
            signature.update(message.getBytes());
            return Base64.toBase64String(signature.sign());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
            throw new CipherException("Failed to do final Cipher", e);
        }
    }

    @Override
    public boolean verify(String publicKey, String message, String signature) throws KeyParseException, CipherException {

        byte[] pubKey = Base64.decode(publicKey);

        X509EncodedKeySpec specPublic = new X509EncodedKeySpec(pubKey);
        PublicKey instanceOfPublicKey = null;

        try {

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            instanceOfPublicKey = keyFactory.generatePublic(specPublic);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyParseException("Failed to parse Key", e);
        }

        try {
            Signature algorithm = Signature.getInstance(ALGORITHM, PROVIDER);
            algorithm.initVerify(instanceOfPublicKey);
            algorithm.update(message.getBytes());
            return algorithm.verify(Base64.decode(signature));
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CipherException("Failed to do final Cipher", e);
        }
    }

    public KeyPairDTO generateKeyPair() throws ServerException {
        try {
            return new KeyPairDTO(generateKeys());
        } catch (Exception e) {
            throw new ServerException("Could not generate key pair", e);
        }
    }
}
