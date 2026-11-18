/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
package edu.mycoin;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationTest {

    // ── Wallet: sign/verify round-trip ───────────────────────────────────

    @Test void signAndVerifyRoundTrip() {
        Wallet w = new Wallet();
        byte[] msg = "hello".getBytes();
        byte[] sig = w.sign(msg);
        assertTrue(Wallet.verify(w.publicKeyBytes(), msg, sig));
    }

    @Test void tamperedMessageFailsVerification() {
        Wallet w = new Wallet();
        byte[] sig = w.sign("hello".getBytes());
        assertFalse(Wallet.verify(w.publicKeyBytes(), "HELLO".getBytes(), sig));
    }

    @Test void wrongKeyFailsVerification() {
        Wallet a = new Wallet();
        Wallet b = new Wallet();
        byte[] sig = a.sign("x".getBytes());
        assertFalse(Wallet.verify(b.publicKeyBytes(), "x".getBytes(), sig));
    }

    @Test void addressesAreDeterministicAndDistinct() {
        Wallet a = new Wallet();
        Wallet b = new Wallet();
        assertNotEquals(a.address(), b.address());
        assertEquals(a.address(), Wallet.deriveAddress(a.publicKey()));
    }

    @Test void watchOnlyWalletCannotSign() {
        Wallet w = new Wallet();
        Wallet watch = Wallet.fromPublicKey(w.publicKeyBytes());
        assertEquals(w.address(), watch.address());
        assertFalse(watch.canSign());
        assertThrows(IllegalStateException.class, () -> watch.sign(new byte[]{1}));
    }

    @Test void fromKeyPairBytesRoundTrip() {
        Wallet w = new Wallet();
        Wallet reloaded = Wallet.fromKeyPairBytes(w.privateKeyBytes(), w.publicKeyBytes());
        assertEquals(w.address(), reloaded.address());
        byte[] msg = "round trip".getBytes();
        assertTrue(Wallet.verify(reloaded.publicKeyBytes(), msg, reloaded.sign(msg)));
    }

    @Test void mismatchedKeyPairRejected() {
        Wallet a = new Wallet();
        Wallet b = new Wallet();
        assertThrows(IllegalArgumentException.class,
            () -> Wallet.fromKeyPairBytes(a.privateKeyBytes(), b.publicKeyBytes()));
    }

    // ── UTXOSet: a small scenario harness ────────────────────────────────

    /** A block with one coinbase paying `amount` to `to`. */
    private static Block coinbaseBlock(String to, long amount, String prevHash, long nonce) {
        Transaction cb = Transaction.coinbase(to, amount);
        return Block.seal(prevHash, 0L, 0, nonce, 0, List.of(cb));
    }

    /** Builds a signed spend of {@code utxo} from {@code from}, paying {@code to} {@code amountOut}. */
    private static Transaction spend(Wallet from, String prevTxId, int outIndex,
                                     long amountIn, String to, long amountOut) {
        // Build a dummy input with empty signature, to get the sighash.
        Transaction.Input dummy = new Transaction.Input(prevTxId, outIndex, new byte[]{0}, from.publicKeyBytes());
        Transaction template = Transaction.create(
            List.of(dummy),
            List.of(new Transaction.Output(amountOut, to)),
            0L);
        byte[] sighash = template.sighash(0);
        byte[] sig = from.sign(sighash);
        Transaction.Input signed = new Transaction.Input(prevTxId, outIndex, sig, from.publicKeyBytes());
        return Transaction.create(
            List.of(signed),
            List.of(new Transaction.Output(amountOut, to)),
            0L);
    }

    // ── Apply block: happy path ─────────────────────────────────────────

    @Test void coinbaseAppliesAndCreditsAddress() {
        Wallet miner = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet.ApplyResult r = new UTXOSet().applyBlock(cb, 50L);
        assertEquals(50L, r.newSet().balanceOf(miner.address()));
    }

    @Test void simpleSpendTransfersBalance() {
        Wallet miner = new Wallet();
        Wallet alice = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet afterCb = new UTXOSet().applyBlock(cb, 50L).newSet();

        String cbTxId = cb.transactions().get(0).txId();
        Transaction pay = spend(miner, cbTxId, 0, 50L, alice.address(), 40L);
        Block spendBlock = Block.seal(cb.hash(), 0L, 0, 1, 0, List.of(pay));

        UTXOSet afterSpend = afterCb.applyBlock(spendBlock, 50L).newSet();
        assertEquals(0L, afterSpend.balanceOf(miner.address()));
        assertEquals(40L, afterSpend.balanceOf(alice.address()));
    }

    // ── Rejections ──────────────────────────────────────────────────────

    @Test void spendingNonexistentUtxoIsRejected() {
        Wallet alice = new Wallet();
        Transaction pay = spend(alice, "aa".repeat(32), 0, 1L, alice.address(), 1L);
        Block b = Block.seal(Block.ZERO_HASH, 0L, 0, 0, 0, List.of(pay));
        assertThrows(UTXOSet.InvalidBlockException.class, () -> new UTXOSet().applyBlock(b, 0L));
    }

    @Test void doubleSpendWithinBlockIsRejected() {
        Wallet miner = new Wallet();
        Wallet alice = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet set = new UTXOSet().applyBlock(cb, 50L).newSet();
        String cbTxId = cb.transactions().get(0).txId();

        Transaction pay1 = spend(miner, cbTxId, 0, 50L, alice.address(), 10L);
        Transaction pay2 = spend(miner, cbTxId, 0, 50L, alice.address(), 10L);
        Block b = Block.seal(cb.hash(), 0L, 0, 1, 0, List.of(pay1, pay2));

        assertThrows(UTXOSet.InvalidBlockException.class, () -> set.applyBlock(b, 50L));
    }

    @Test void unsignedInputIsRejected() {
        Wallet miner = new Wallet();
        Wallet alice = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet set = new UTXOSet().applyBlock(cb, 50L).newSet();
        String cbTxId = cb.transactions().get(0).txId();

        Transaction.Input unsigned = new Transaction.Input(cbTxId, 0, new byte[]{0}, alice.publicKeyBytes());
        Transaction pay = Transaction.create(
            List.of(unsigned), List.of(new Transaction.Output(10L, alice.address())), 0L);
        Block b = Block.seal(cb.hash(), 0L, 0, 1, 0, List.of(pay));

        assertThrows(UTXOSet.InvalidBlockException.class, () -> set.applyBlock(b, 50L));
    }

    @Test void wrongSignerIsRejected() {
        Wallet miner = new Wallet();
        Wallet thief = new Wallet();
        Wallet alice = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet set = new UTXOSet().applyBlock(cb, 50L).newSet();
        String cbTxId = cb.transactions().get(0).txId();

        // Thief tries to sign the spend of the miner's UTXO with thief's key.
        Transaction pay = spend(thief, cbTxId, 0, 50L, alice.address(), 10L);
        Block b = Block.seal(cb.hash(), 0L, 0, 1, 0, List.of(pay));

        assertThrows(UTXOSet.InvalidBlockException.class, () -> set.applyBlock(b, 50L));
    }

    @Test void inflationIsRejected() {
        Wallet miner = new Wallet();
        Wallet alice = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 50L, Block.ZERO_HASH, 0);
        UTXOSet set = new UTXOSet().applyBlock(cb, 50L).newSet();
        String cbTxId = cb.transactions().get(0).txId();

        // Sign with correct miner key, but outputs sum > inputs.
        Transaction.Input dummy = new Transaction.Input(cbTxId, 0, new byte[]{0}, miner.publicKeyBytes());
        Transaction template = Transaction.create(
            List.of(dummy), List.of(new Transaction.Output(60L, alice.address())), 0L);
        byte[] sig = miner.sign(template.sighash(0));
        Transaction.Input signed = new Transaction.Input(cbTxId, 0, sig, miner.publicKeyBytes());
        Transaction pay = Transaction.create(
            List.of(signed), List.of(new Transaction.Output(60L, alice.address())), 0L);
        Block b = Block.seal(cb.hash(), 0L, 0, 1, 0, List.of(pay));

        assertThrows(UTXOSet.InvalidBlockException.class, () -> set.applyBlock(b, 50L));
    }

    @Test void coinbaseOverMintIsRejected() {
        Wallet miner = new Wallet();
        Block cb = coinbaseBlock(miner.address(), 100L, Block.ZERO_HASH, 0);
        assertThrows(UTXOSet.InvalidBlockException.class,
            () -> new UTXOSet().applyBlock(cb, 50L));
    }

    @Test void multipleCoinbasesRejected() {
        Wallet a = new Wallet();
        Transaction cb1 = Transaction.coinbase(a.address(), 10L);
        Transaction cb2 = Transaction.coinbase(a.address(), 10L);
        Block b = Block.seal(Block.ZERO_HASH, 0L, 0, 0, 0, List.of(cb1, cb2));
        assertThrows(UTXOSet.InvalidBlockException.class,
            () -> new UTXOSet().applyBlock(b, 50L));
    }
}
