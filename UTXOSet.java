/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Unspent Transaction Output set — the state of the chain.
 *
 * <p>Mutating APIs are package-private: only {@link Blockchain} may call
 * {@link #applyBlock(Block, long)}. External code can query but not mint.</p>
 *
 * <p>{@link #applyBlock(Block, long)} validates the whole block atomically:
 * either every transaction is valid and the set transitions, or an exception
 * is thrown and the set is unchanged.</p>
 */
public final class UTXOSet {

    /** Result of applying a block: the new set, and the fees it collected. */
    public record ApplyResult(UTXOSet newSet, long fees) {}

    private final Map<String, Transaction.Output> utxos;

    public UTXOSet() { this.utxos = new HashMap<>(); }

    private UTXOSet(Map<String, Transaction.Output> utxos) { this.utxos = utxos; }

    // ── Queries (public) ─────────────────────────────────────────────────

    public Optional<Transaction.Output> get(String outpoint) {
        return Optional.ofNullable(utxos.get(outpoint));
    }

    public boolean contains(String outpoint) { return utxos.containsKey(outpoint); }

    public int size() { return utxos.size(); }

    public long balanceOf(String address) {
        if (address == null) return 0;
        long sum = 0;
        for (Transaction.Output o : utxos.values()) {
            if (address.equals(o.address())) sum += o.amount();
        }
        return sum;
    }

    public static String outpoint(String txId, int index) {
        return txId + ":" + index;
    }

    /** Snapshot copy for {@link BlockchainStorage} or tests. */
    public Map<String, Transaction.Output> snapshot() {
        return Map.copyOf(utxos);
    }

    // ── Application (package-private: only Blockchain calls this) ───────

    /**
     * Validates and applies a block. Throws {@link InvalidBlockException} on
     * any consensus failure; on success returns the new set (this one is
     * unchanged) and the total fees collected.
     *
     * @param block      the block to apply
     * @param subsidy    the coinbase subsidy for this block (height-dependent,
     *                   passed in so the set doesn't need to know chain state)
     */
    ApplyResult applyBlock(Block block, long subsidy) {
        Objects.requireNonNull(block, "block");
        if (subsidy < 0) throw new IllegalArgumentException("subsidy < 0");

        Map<String, Transaction.Output> next = new HashMap<>(utxos);
        Set<String> spentThisBlock = new HashSet<>();
        long feesCollected = 0;
        boolean coinbaseSeen = false;

        for (Transaction tx : block.transactions()) {
            if (tx.isCoinbase()) {
                if (coinbaseSeen) throw new InvalidBlockException("multiple coinbase txs");
                coinbaseSeen = true;
                long outSum = 0;
                for (Transaction.Output o : tx.outputs()) outSum = Math.addExact(outSum, o.amount());
                long cap = Math.addExact(subsidy, feesCollected);
                if (outSum > cap) {
                    throw new InvalidBlockException(
                        "coinbase over-mints: out=" + outSum + " cap=" + cap);
                }
                addOutputs(next, tx);
            } else {
                long inSum = 0;
                for (int i = 0; i < tx.inputs().size(); i++) {
                    Transaction.Input in = tx.inputs().get(i);
                    String key = outpoint(in.prevTxId(), in.outputIndex());
                    if (!spentThisBlock.add(key)) {
                        throw new InvalidBlockException("double-spend within block: " + key);
                    }
                    Transaction.Output prev = next.remove(key);
                    if (prev == null) throw new InvalidBlockException("missing UTXO: " + key);

                    // Address binding: derive the address from the supplied
                    // pubkey and require it to match the output's address.
                    String signer;
                    try {
                        signer = Wallet.deriveAddress(
                            java.security.KeyFactory.getInstance("EC")
                                .generatePublic(new java.security.spec.X509EncodedKeySpec(in.publicKey())));
                    } catch (java.security.GeneralSecurityException e) {
                        throw new InvalidBlockException("malformed publicKey", e);
                    }
                    if (!prev.address().equals(signer)) {
                        throw new InvalidBlockException("signer is not the output owner: " + key);
                    }

                    // Signature check over the input's sighash.
                    byte[] sighash = tx.sighash(i);
                    if (!Wallet.verify(in.publicKey(), sighash, in.signature())) {
                        throw new InvalidBlockException("bad signature for input " + i);
                    }

                    inSum = Math.addExact(inSum, prev.amount());
                }
                long outSum = 0;
                for (Transaction.Output o : tx.outputs()) outSum = Math.addExact(outSum, o.amount());
                if (inSum < outSum) {
                    throw new InvalidBlockException("inflation: in=" + inSum + " out=" + outSum);
                }
                feesCollected = Math.addExact(feesCollected, inSum - outSum);
                addOutputs(next, tx);
            }
        }
        return new ApplyResult(new UTXOSet(next), feesCollected);
    }

    private static void addOutputs(Map<String, Transaction.Output> map, Transaction tx) {
        for (int i = 0; i < tx.outputs().size(); i++) {
            map.put(outpoint(tx.txId(), i), tx.outputs().get(i));
        }
    }

    // ── Exception ─────────────────────────────────────────────────────────

    public static final class InvalidBlockException extends RuntimeException {
        public InvalidBlockException(String msg) { super(msg); }
        public InvalidBlockException(String msg, Throwable cause) { super(msg, cause); }
    }
}