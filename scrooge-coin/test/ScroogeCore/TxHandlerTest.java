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
    void shouldAcceptThisTransactionWith3OutputsV2() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        ArrayList<Tuple<Double, PublicKey>> outputs = new ArrayList<Tuple<Double, PublicKey>>();

        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(80), validPublicKeys.get(0)));
        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Transaction txn = makeTxn(0, 0, outputs, pk);

        assert(txHandler.isValidTx(txn));
    }

    @Test
    void shouldHandleTxnWithSameInputsTxns() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        ArrayList<Tuple<Double, PublicKey>> outputs = new ArrayList<Tuple<Double, PublicKey>>();
        ArrayList<Tuple<Double, PublicKey>> outputs2 = new ArrayList<Tuple<Double, PublicKey>>();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(80), validPublicKeys.get(0)));

        outputs2.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(3)));
        outputs2.add(new Tuple<Double, PublicKey>(new Double(50), validPublicKeys.get(0)));

        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Transaction txn = makeTxn(0, 0, outputs, pk);
        Transaction txn1 = makeTxn(0, 0, outputs2, pk);
        Transaction[] txns = new Transaction[2];
        txns[0] = txn; txns[1] = txn1;
        assert(txHandler.handleTxs(txns).length == 1);
    }

    @Test
    void shouldHandleTxnWithSameTxnsTwice() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        ArrayList<Tuple<Double, PublicKey>> outputs = new ArrayList<Tuple<Double, PublicKey>>();
        ArrayList<Tuple<Double, PublicKey>> outputs2 = new ArrayList<Tuple<Double, PublicKey>>();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(80), validPublicKeys.get(0)));

        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Transaction txn = makeTxn(0, 0, outputs, pk);
        Transaction[] txns = new Transaction[1];
        txns[0] = txn;
        assert(txHandler.handleTxs(txns).length == 1);

        assert(txHandler.handleTxs(txns).length == 0);
    }

    @Test
    void shouldHandleTxnWithSimpleTxnsOneAfterAnother() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        ArrayList<Tuple<Double, PublicKey>> outputs = new ArrayList<Tuple<Double, PublicKey>>();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(80), validPublicKeys.get(0)));

        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Transaction txn = makeTxn(0, 0, outputs, pk);
        Transaction[] txns = new Transaction[1];
        txns[0] = txn;
        Transaction[] tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 1);
        assert(txHandler.getPool().getAllUTXO().size() == 2);

        UTXO utxo = new UTXO(tApplied[0].getHash(), 1);
        outputs.clear();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(60), validPublicKeys.get(0)));
        txn = makeTxnWithUTXO(utxo, outputs, pk);
        txns[0] = txn;
        tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 1);
        assert(txHandler.getPool().getAllUTXO().size() == 3);

        utxo = new UTXO(tApplied[0].getHash(), 1);
        outputs.clear();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(50), validPublicKeys.get(0)));
        txn = makeTxnWithUTXO(utxo, outputs, pk);
        txns[0] = txn;
        tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 1);
        assert(txHandler.getPool().getAllUTXO().size() == 4);

        utxo = new UTXO(tApplied[0].getHash(), 0);
        outputs.clear();
        outputs.add(new Tuple<Double, PublicKey>(new Double(5), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(5), validPublicKeys.get(0)));
        txn = makeTxnWithUTXO(utxo, outputs, validKeyPairs.get(validPublicKeys.get(1)));
        txns[0] = txn;
        tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 1);
        assert(txHandler.getPool().getAllUTXO().size() == 5);
    }

    @Test
    void shouldHandleTxnWithMultipleValidTxns() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        TxHandler txHandler = new TxHandler(testPool);
        ArrayList<Tuple<Double, PublicKey>> outputs = new ArrayList<Tuple<Double, PublicKey>>();
        outputs.add(new Tuple<Double, PublicKey>(new Double(10), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(80), validPublicKeys.get(0)));

        PrivateKey pk = validKeyPairs.get(validPublicKeys.get(0));
        Transaction txn = makeTxn(0, 0, outputs, pk);
        Transaction[] txns = new Transaction[1];
        txns[0] = txn;
        Transaction[] tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 1);
        assert(txHandler.getPool().getAllUTXO().size() == 2);

        // now make 4 coins
        UTXO utxo = new UTXO(tApplied[0].getHash(), 1);
        outputs.clear();
        outputs.add(new Tuple<Double, PublicKey>(new Double(5), validPublicKeys.get(1)));
        outputs.add(new Tuple<Double, PublicKey>(new Double(75), validPublicKeys.get(0)));
        txn = makeTxnWithUTXO(utxo, outputs, pk);

        ArrayList<Tuple<Double, PublicKey>> outputs2 = new ArrayList<Tuple<Double, PublicKey>>();
        utxo = new UTXO(tApplied[0].getHash(), 0);
        outputs2.add(new Tuple<Double, PublicKey>(new Double(5), validPublicKeys.get(1)));
        outputs2.add(new Tuple<Double, PublicKey>(new Double(5), validPublicKeys.get(0)));
        Transaction txn1 = makeTxnWithUTXO(utxo, outputs2, validKeyPairs.get(validPublicKeys.get(1)));

        txns = new Transaction[2];
        txns[0] = txn; txns[1] = txn1;

        tApplied = txHandler.handleTxs(txns);

        assert(tApplied.length == 2);
        assert(txHandler.getPool().getAllUTXO().size() == 4);
    }

    private Transaction makeTxnWithUTXO(UTXO utxo, ArrayList<Tuple<Double, PublicKey>> outputs, PrivateKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        for (Tuple<Double, PublicKey> output : outputs) {
            transaction.addOutput(output.x, output.y);
        }
        transaction.addInput(utxo.getTxHash(), utxo.getIndex());

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        return transaction;
    }

    private Transaction makeTxn(int inputUTXO, int utxoOutputIndex, ArrayList<Tuple<Double, PublicKey>> outputs, PrivateKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sigInstance = Signature.getInstance("SHA256withRSA");
        sigInstance.initSign(pk);

        Transaction transaction = new Transaction();
        for (Tuple<Double, PublicKey> output : outputs) {
            transaction.addOutput(output.x, output.y);
        }
        transaction.addInput(testPool.getAllUTXO().get(inputUTXO).getTxHash(), utxoOutputIndex);

        sigInstance.update(transaction.getRawDataToSign(0));
        byte[] signature = sigInstance.sign();

        transaction.addSignature(signature, 0);
        transaction.finalize();

        return transaction;
    }

    public class Tuple<X, Y> {
        public final X x;
        public final Y y;
        public Tuple(X x, Y y) {
            this.x = x;
            this.y = y;
        }
    }

}