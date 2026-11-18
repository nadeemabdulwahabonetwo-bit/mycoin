/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import java.util.List;

/**
 * Runnable demo of the Phase 3 API. No storage, no network.
 * Run as {@code java edu.mycoin.Playground}.
 */
public final class Playground {

    public static void main(String[] args) {
        // 1. Genesis: mine a coinbase to a miner wallet.
        Wallet miner = new Wallet();
        Transaction cb0 = Transaction.coinbase(miner.address(), Blockchain.SUBSIDY);
        Block genesis = Block.seal(
            Block.ZERO_HASH, System.currentTimeMillis(), 1, 0, 0, List.of(cb0));

        MiningEngine.MiningResult g = MiningEngine.mineDeterministic(genesis, 1_000_000);
        require(g.success(), "genesis mining failed");
        Blockchain bc = new Blockchain();
        bc.addGenesis(g.mined());
        System.out.println("Genesis accepted. Miner balance: " + bc.balanceOf(miner.address()));

        // 2. Alice receives a payment from the miner.
        Wallet alice = new Wallet();
        String cbTxId = g.mined().transactions().get(0).txId();

        // Build the payment in two steps: sign over sighash, then attach signature.
        Transaction.Input dummy = new Transaction.Input(
            cbTxId, 0, new byte[]{0}, miner.publicKeyBytes());
        Transaction template = Transaction.create(
            List.of(dummy),
            List.of(new Transaction.Output(30L, alice.address())),
            0L);
        byte[] sig = miner.sign(template.sighash(0));
        Transaction pay = Transaction.create(
            List.of(new Transaction.Input(cbTxId, 0, sig, miner.publicKeyBytes())),
            List.of(new Transaction.Output(30L, alice.address())),
            0L);

        Block payTemplate = Block.seal(
            bc.latest().hash(), System.currentTimeMillis(), 1, 0, 0, List.of(pay));
        MiningEngine.MiningResult m = MiningEngine.mineDeterministic(payTemplate, 1_000_000);
        require(m.success(), "payment block mining failed");

        Blockchain.AddResult r = bc.addBlock(m.mined());
        require(r.accepted(), "addBlock rejected: " + r.reason());
        System.out.println("Payment block accepted. Fees=" + r.fees());
        System.out.println("Miner balance: " + bc.balanceOf(miner.address()));
        System.out.println("Alice balance: " + bc.balanceOf(alice.address()));

        // 3. Replay from the snapshot to prove the chain is self-validating.
        Blockchain replayed = Blockchain.replayAndValidate(bc.snapshot());
        require(replayed.latest().hash().equals(bc.latest().hash()), "replay mismatch");
        System.out.println("Replay OK. Height=" + replayed.height());
    }

    private static void require(boolean ok, String msg) {
        if (!ok) throw new IllegalStateException(msg);
    }

    private Playground() {}
}
