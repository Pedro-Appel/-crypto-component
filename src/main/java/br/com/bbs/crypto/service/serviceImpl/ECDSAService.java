package br.com.bbs.crypto.service.serviceImpl;

import br.com.bbs.crypto.model.dto.KeyPairDTO;
import br.com.bbs.crypto.service.SignatureService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.management.InvalidApplicationException;
import java.security.*;
import java.security.spec.*;
public class ECDSAService implements SignatureService {
    public ECDSAService() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeys() {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            SecureRandom random = SecureRandom.getInstanceStrong();
            ECGenParameterSpec params = new ECGenParameterSpec("prime256v1");
            keyPairGenerator.initialize(params, random);
            return keyPairGenerator.generateKeyPair();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public String sign(String privateKey, String message) {

        byte[] pubKeyBytes = Base64.decode(privateKey);
        KeySpec keySpec = new PKCS8EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = null;
        PrivateKey instanceOfPrivateKey = null;
        try {
            keyFactory = KeyFactory.getInstance("ECDSA");
            instanceOfPrivateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        Signature signature;

        try {
            signature = Signature.getInstance("ECDSA","BC");
            signature.initSign(instanceOfPrivateKey);
            signature.update(message.getBytes());
            return Base64.toBase64String(signature.sign());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(String publicKey, String message, String signature) throws InvalidApplicationException {

        byte[] pubKey = Base64.decode(publicKey);

        X509EncodedKeySpec specPublic = new X509EncodedKeySpec(pubKey);
        PublicKey instanceOfPublicKey = null;

        try {

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            instanceOfPublicKey = keyFactory.generatePublic(specPublic);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new InvalidApplicationException(e);
        }

        try {
            Signature algorithm = Signature.getInstance("ECDSA", "BC");
            algorithm.initVerify(instanceOfPublicKey);
            algorithm.update(message.getBytes());
            return algorithm.verify(Base64.decode(signature));
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidApplicationException(e);
        }
    }

    public KeyPairDTO generateKeyPair() {
        return new KeyPairDTO(generateKeys());
    }
}
