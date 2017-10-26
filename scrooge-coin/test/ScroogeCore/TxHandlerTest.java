package ScroogeCore;

import org.junit.jupiter.api.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ramneek on 26/10/17.
 */
class TxHandlerTest {
    static String plaintext = "This is the message being signed";
    static byte[] genesisPrevBlockHash = "GenesisBlock".getBytes(); // change this to use md5

    static Map<PublicKey, PrivateKey> validKeyPairs = new ConcurrentHashMap<>();
    static ArrayList<PublicKey> validPublicKeys = new ArrayList<>();

    static UTXOPool testPool;

    static void testKey(KeyPair k) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(k.getPrivate());
        sigInstance.update((plaintext).getBytes());
        byte[] signature = sigInstance.sign();

        assert(Crypto.verifySignature(k.getPublic(), plaintext.getBytes(), signature) == true);
    }

    static void createPoolWithGenesisBlock(double val) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        UTXOPool pool = new UTXOPool();

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

        assert(Crypto.verifySignature(validPublicKeys.get(0), transaction.getRawDataToSign(0), signature) == true);

        UTXO utxo = new UTXO(transaction.getHash(), 0);
        pool.addUTXO(utxo, transaction.getOutput(0));

        testPool = pool;
    }

    static void createTestKeys(int num) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException {
        for (int i = 0; i < num; i++) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            KeyPair k = keyGen.generateKeyPair();
            validKeyPairs.put(k.getPublic(), k.getPrivate());
            validPublicKeys.add(k.getPublic());
            testKey(k);
        }
    }

    @BeforeEach
    void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException {
        createTestKeys(5);
        createPoolWithGenesisBlock(100.00);
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void shouldAcceptThisTransaction() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(90, validPublicKeys.get(0));
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction));

        //txHandler.handleTxs();
    }

    @Test
    void shouldAcceptThisTransactionWith3Outputs() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(10, validPublicKeys.get(2));
        transaction.addOutput(80, validPublicKeys.get(0));
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction));
    }

    @Test
    void shouldFailThisTransactionIncorrectHash() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(90, validPublicKeys.get(0));
        transaction.addInput("IncorrectHash".getBytes(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction) == false);
    }

    @Test
    void shouldFailThisTransactionInputLesserThanOutput() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(100, validPublicKeys.get(0));
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction) == false);
    }

    @Test
    void shouldFailThisTransactionInputUsingSameUTXOTwice() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(90, validPublicKeys.get(0));
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.addSignature(signature, 1);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction) == false);
    }

    @Test
    void shouldFailThisTransactionIncorrectSig() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(1));
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        transaction.addOutput(10, validPublicKeys.get(1));
        transaction.addOutput(90, validPublicKeys.get(0));
        transaction.addInput(testPool.getAllUTXO().get(0).getTxHash(), 0);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        assert(txHandler.isValidTx(transaction) == false);
    }

    @Test
    void handleTxs() {
    }

}