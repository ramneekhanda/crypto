package ScroogeCore;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;

public class TxHandler {
    UTXOPool pool;

    public UTXOPool getPool() { return pool; }
    public enum ThreeState {
        TRUE,
        FALSE,
        MAYBE
    };

    /**
     * Creates a public ledger whose current ScroogeCore.UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the ScroogeCore.UTXOPool(ScroogeCore.UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        pool = utxoPool;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current ScroogeCore.UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no ScroogeCore.UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        HashSet<UTXO> utxoSet = new HashSet<>();
        double sumOfInputVals = 0, sumOfOutputVals = 0;
        int i = 0;
        for (Transaction.Input input: tx.getInputs()) {
            UTXO lastUTXO = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output prevTx = pool.getTxOutput(lastUTXO);
            // check 1 - all output claimed by tx are in current utxopool
            if (!pool.contains(lastUTXO)) {
                return false;
            }
            // check 2 - signatures of each input are valid
            if (input.signature == null || !Crypto.verifySignature(prevTx.address, tx.getRawDataToSign(i), input.signature)) {
                return false;
            }
            utxoSet.add(lastUTXO);
            sumOfInputVals += prevTx.value;
            i++;
        }

        // check 3 - no utxo is claimed multiple times
        if (utxoSet.size() != tx.getInputs().size())
            return false;

        // check 4 - non negative output values
        for (Transaction.Output output: tx.getOutputs()) {
            sumOfOutputVals += output.value;
            if (output.value < 0)
                return false;
        }

        // check 5 - validating input values >= sum of output values
        if (sumOfInputVals < sumOfOutputVals)
            return false;

        return true;
    }

    public ThreeState isValidTxV2(Transaction tx) {
        HashSet<UTXO> utxoSet = new HashSet<>();
        double sumOfInputVals = 0, sumOfOutputVals = 0;
        int i = 0;
        for (Transaction.Input input: tx.getInputs()) {
            UTXO lastUTXO = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output prevTx = pool.getTxOutput(lastUTXO);
            // check 1 - all output claimed by tx are in current utxopool
            if (!pool.contains(lastUTXO)) {
                return ThreeState.MAYBE;
            }
            // check 2 - signatures of each input are valid
            if (input.signature == null || !Crypto.verifySignature(prevTx.address, tx.getRawDataToSign(i), input.signature)) {
                return ThreeState.FALSE;
            }
            utxoSet.add(lastUTXO);
            sumOfInputVals += prevTx.value;
            i++;
        }

        // check 3 - no utxo is claimed multiple times
        if (utxoSet.size() != tx.getInputs().size())
            return ThreeState.FALSE;

        // check 4 - non negative output values
        for (Transaction.Output output: tx.getOutputs()) {
            sumOfOutputVals += output.value;
            if (output.value < 0)
                return ThreeState.FALSE;
        }

        // check 5 - validating input values >= sum of output values
        if (sumOfInputVals < sumOfOutputVals)
            return ThreeState.FALSE;;

        return ThreeState.TRUE;
    }

    private static <T> BinaryOperator<ArrayList<T>> arrayListMerger() {
        return (u,v) -> { ArrayList<T> temp = new ArrayList<>(); temp.addAll(u); temp.addAll(v); return temp; };
    }

    private Map<ComparableTransactionInput, ArrayList<Transaction>> getInputTransactionMap(ArrayList<Transaction> iValidTxns) {

        Map<ComparableTransactionInput, ArrayList<Transaction>> inputTxn = iValidTxns.stream().map(tx -> {
            Map<ComparableTransactionInput, ArrayList<Transaction>> inputTxMap = new HashMap<ComparableTransactionInput, ArrayList<Transaction>>();
            ArrayList<Transaction> at = new ArrayList<Transaction>();
            at.add(tx);
            for (Transaction.Input input : tx.getInputs()) {
                inputTxMap.put(new ComparableTransactionInput(input.prevTxHash, input.outputIndex), at);
            }
            return inputTxMap;
        }).map(Map::entrySet).flatMap(Set::stream)
                .collect(
                        Collectors.toMap(
                                Entry::getKey,
                                Entry::getValue,
                                arrayListMerger()
                        ));
//                collect(,
//                (reducedMap, inputTxMap) -> {
//                    Set<ComparableTransactionInput> keys = inputTxMap.keySet();
//                    for (ComparableTransactionInput input : keys) {
//                        if (reducedMap.containsKey(input)) {
//                            ArrayList<Transaction> currTxns = reducedMap.remove(input);
//                            currTxns.addAll(inputTxMap.get(input));
//                            reducedMap.put(input, currTxns);
//                        } else {
//                            reducedMap.put(input, inputTxMap.get(input));
//                        }
//                    }
//                    return reducedMap;
//                });

        return inputTxn;
    }



    private boolean checkIfMutuallyValid(ArrayList<Transaction> goodTxnSet, Transaction tx, UTXOPool pool) {
        double sumOfInputVals = 0.0, sumOfOutputVals = 0.0;
        goodTxnSet.add(tx);
        Map<ComparableTransactionInput, ArrayList<Transaction>> inputTransactionMap = getInputTransactionMap(goodTxnSet);

        for (ComparableTransactionInput input : inputTransactionMap.keySet()) {
            UTXO lastUTXO = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output prevTx = pool.getTxOutput(lastUTXO);
            sumOfInputVals += prevTx.value;
        }

        for (Transaction gTxn : goodTxnSet) {
            for (Transaction.Output output: gTxn.getOutputs()) {
                sumOfOutputVals += output.value;
            }
        }

        if (sumOfInputVals < sumOfOutputVals)
            return false;

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current ScroogeCore.UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        UTXOPool tempPool = new UTXOPool(pool);

        ArrayList<Transaction> mValidTxns = new ArrayList<>(); // mutually valid txns
        ArrayList<Transaction> ignoredValidTxns = new ArrayList<>();  // independently valid txns
        ArrayList<Transaction> iValidTxns = new ArrayList<>();  // independently valid txns
        ArrayList<Transaction> pendingTxns = new ArrayList<>();  // txns which may depend on other txns in this set

        // filter out transactions that depend on the current set of transactions.. these will be looked at last
        // definition of depends - tx ref is of one that doesn't exist in utxo pool
        // step 1 find out independently valid transactions and possible dependent txns..
        for (Transaction tx: possibleTxs) {
            if (isValidTxV2(tx) == ThreeState.TRUE)
                iValidTxns.add(tx);
            else if (isValidTxV2(tx) == ThreeState.MAYBE)
                pendingTxns.add(tx);
        }

        while (iValidTxns.size() != 0) {
            Transaction tx = iValidTxns.get(0);
            if (checkIfMutuallyValid(new ArrayList<>(mValidTxns), tx, pool)) {
                mValidTxns.add(tx);
                iValidTxns.remove(0);
            } else {
                ignoredValidTxns.add(tx);
                iValidTxns.remove(0);
            }
        }

        for (Transaction txn : mValidTxns) {
            for (Transaction.Input input : txn.getInputs()) { // remove utxos that have been spent
                UTXO lastUTXO = new UTXO(input.prevTxHash, input.outputIndex);
                tempPool.removeUTXO(lastUTXO);
            }
            int idx = 0;
            for (Transaction.Output out : txn.getOutputs()) {
                UTXO utxo = new UTXO(txn.getHash(), idx);
                tempPool.addUTXO(utxo, out);
                idx++;
            }
        }

        pool = tempPool;
        Transaction[] retVal = new Transaction[mValidTxns.size()];
        retVal = mValidTxns.toArray(retVal);
        return retVal;
    }


    private class ComparableTransactionInput {
        public byte[] prevTxHash;
        public int outputIndex;

        public ComparableTransactionInput(byte[] prevHash, int index) {
            if (prevHash == null)
                prevTxHash = null;
            else
                prevTxHash = Arrays.copyOf(prevHash, prevHash.length);
            outputIndex = index;
        }

        public boolean equals(Object other) {
            if (other != null && Arrays.equals(((ComparableTransactionInput)other).prevTxHash, prevTxHash) && ((ComparableTransactionInput)other).outputIndex == outputIndex)
                return true;
            else
                return false;
        }

        public int hashCode() {
            int sum = outputIndex;
            for (byte b: prevTxHash) sum += b;
            return sum;
        }
    }

}
