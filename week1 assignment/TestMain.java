/**
 * Created by ramneek on 26/10/17.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TestMain {
    static String plaintext = "This is the message being signed";
    static byte[] genesisPrevBlockHash = "GenesisBlock".getBytes(); // change this to use md5

    static Map<PublicKey, PrivateKey> validKeyPairs = new ConcurrentHashMap<>();
    static ArrayList<PublicKey> validPublicKeys = new ArrayList<>();

    static void testKey(KeyPair k) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(k.getPrivate());
        sigInstance.update((plaintext).getBytes());
        byte[] signature = sigInstance.sign();

        assert(Crypto.verifySignature(k.getPublic(), plaintext.getBytes(), signature) == true);
    }

    static Transaction createGenesisBlock(double val) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(val, validPublicKeys.get(0));
        transaction.addInput(genesisPrevBlockHash, 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();
        System.out.println(transaction.getHash());

        assert(Crypto.verifySignature(validPublicKeys.get(0), transaction.getRawDataToSign(0), signature) == true);
        return transaction;
    }

    static void createTestKeys() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException {
        for (int i = 0; i < 5; i++) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            KeyPair k = keyGen.generateKeyPair();
            validKeyPairs.put(k.getPublic(), k.getPrivate());
            validPublicKeys.add(k.getPublic());
            testKey(k);
        }
    }

//    static UTXOPool createUTXOPoolWithGenesisBlock() {
////        UTXOPool utxoPool = new UTXOPool();
////        UTXO genesisUTXO = new UTXO();
////        utxoPool.addUTXO();
//
//        return utxoPool;
//    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        createTestKeys();
        Transaction txG = createGenesisBlock(100.00);
        UTXOPool pool = new UTXOPool();
        UTXO utxo = new UTXO(txG.getHash(), 0);
        pool.addUTXO(utxo, txG.getOutput(0));
    }
}
