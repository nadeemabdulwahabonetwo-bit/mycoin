/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package com.mycompany.mavenproject4;

/**
 *
 * @author nadee
 */
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BlockchainTest {

    /** Build a fresh Blockchain with a mined genesis coinbase to `miner`. */
    private static Blockchain freshChain(Wallet miner) {
        Transaction cb = Transaction.coinbase(miner.address(), Blockchain.SUBSIDY);
        Block genesis = Block.seal(
            Block.ZERO_HASH, 0L, /*difficulty=*/0, 0L, 0, List.of(cb));
        Blockchain bc = new Blockchain();
        bc.addGenesis(genesis);
        return bc;
    }

    // ── Genesis ──────────────────────────────────────────────────────────

    @Test void genesisInstallsAndCredits() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);
        assertEquals(1, bc.height());
        assertEquals(Blockchain.SUBSIDY, bc.balanceOf(miner.address()));
    }

    @Test void secondGenesisRejected() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);
        Block another = Block.seal(Block.ZERO_HASH, 0L, 0, 0, 0, List.of());
        assertThrows(IllegalStateException.class, () -> bc.addGenesis(another));
    }

    @Test void genesisWithNonZeroPrevHashRejected() {
        Blockchain bc = new Blockchain();
        Block bad = Block.seal("ff".repeat(32), 0L, 0, 0, 0, List.of());
        assertThrows(IllegalArgumentException.class, () -> bc.addGenesis(bad));
    }

    // ── Mining + append happy path ──────────────────────────────────────

    @Test void minedBlockIsAccepted() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);

        Block template = Block.seal(
            bc.latest().hash(), 1L, /*difficulty=*/1, 0L, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));

        MiningEngine.MiningResult m = MiningEngine.mineDeterministic(template, 10_000);
        assertTrue(m.success(), "should mine difficulty-1 block");

        Blockchain.AddResult r = bc.addBlock(m.mined());
        assertTrue(r.accepted(), r.reason());
        assertEquals(2, bc.height());
        assertEquals(2 * Blockchain.SUBSIDY, bc.balanceOf(miner.address()));
    }

    // ── Rejections ──────────────────────────────────────────────────────

    @Test void wrongPreviousHashIsRejected() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);

        Block orphan = Block.seal(
            "ff".repeat(32), 1L, 0, 0, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));

        Blockchain.AddResult r = bc.addBlock(orphan);
        assertFalse(r.accepted());
        assertTrue(r.reason().contains("previousHash"));
        assertEquals(1, bc.height());   // unchanged
    }

    @Test void blockFailingDifficultyIsRejected() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);

        // Unmined template with high difficulty (extremely unlikely to pass).
        Block bogus = Block.seal(
            bc.latest().hash(), 1L, /*difficulty=*/8, 0L, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));

        Blockchain.AddResult r = bc.addBlock(bogus);
        assertFalse(r.accepted());
        assertTrue(r.reason().toLowerCase().contains("difficulty"));
    }

    @Test void blockWithInvalidTransactionIsRejectedAtomically() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);
        String cbTxId = bc.latest().transactions().get(0).txId();

        // An input spending a nonexistent UTXO.
        Transaction.Input in = new Transaction.Input(
            "aa".repeat(32), 0, new byte[]{0}, miner.publicKeyBytes());
        Transaction bad = Transaction.create(
            List.of(in), List.of(new Transaction.Output(1L, miner.address())), 0L);
        Block block = Block.seal(
            bc.latest().hash(), 1L, 0, 0, 0, List.of(bad));

        Blockchain.AddResult r = bc.addBlock(block);
        assertFalse(r.accepted());
        assertEquals(1, bc.height());   // chain unchanged
        assertEquals(Blockchain.SUBSIDY, bc.balanceOf(miner.address()));   // UTXO unchanged
        assertTrue(bc.utxoSnapshot().contains(cbTxId + ":0"));
    }

    // ── Concurrency: serialized submissions ─────────────────────────────

    @Test void concurrentAddsAreSerialized() throws Exception {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);

        // Build N valid blocks, each extending the previous, and add them
        // concurrently. Only the one matching the current tip can win; the
        // others are rejected. The chain must end at height == accepted+1.
        int n = 8;
        Block[] blocks = new Block[n];
        String prev = bc.latest().hash();
        for (int i = 0; i < n; i++) {
            Block template = Block.seal(prev, i, 0, 0, 0,
                List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));
            // Note: each template's prev is the *same* tip — they're competing.
            blocks[i] = template;
        }

        Thread[] ts = new Thread[n];
        int[] accepted = new int[1];
        for (int i = 0; i < n; i++) {
            Block b = blocks[i];
            ts[i] = new Thread(() -> {
                if (bc.addBlock(b).accepted()) synchronized (accepted) { accepted[0]++; }
            });
            ts[i].start();
        }
        for (Thread t : ts) t.join();

        assertEquals(1, accepted[0], "exactly one competing block should win");
        assertEquals(2, bc.height());
    }

    // ── Replay / validation ─────────────────────────────────────────────

    @Test void replayRebuildsIdenticalState() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);
        Block t = Block.seal(bc.latest().hash(), 1L, 0, 0, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));
        MiningEngine.MiningResult m = MiningEngine.mineDeterministic(t, 10_000);
        assertTrue(m.success());
        assertTrue(bc.addBlock(m.mined()).accepted());

        Blockchain rebuilt = Blockchain.replayAndValidate(bc.snapshot());
        assertEquals(bc.height(), rebuilt.height());
        assertEquals(bc.balanceOf(miner.address()), rebuilt.balanceOf(miner.address()));
        assertEquals(bc.latest().hash(), rebuilt.latest().hash());
    }

    @Test void replayRejectsTamperedChain() {
        Wallet miner = new Wallet();
        Blockchain bc = freshChain(miner);

        Block t = Block.seal(bc.latest().hash(), 1L, 0, 0, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));
        MiningEngine.MiningResult m = MiningEngine.mineDeterministic(t, 10_000);
        assertTrue(m.success());
        assertTrue(bc.addBlock(m.mined()).accepted());

        // Replace the last block with a version claiming a different timestamp
        // → hash no longer matches header. Replay must reject.
        List<Block> tampered = new java.util.ArrayList<>(bc.snapshot());
        Block original = tampered.get(1);
        Block fake = Block.seal(
            original.previousHash(), original.timestamp() + 1,
            original.difficultyTarget(), original.nonce(), original.citySeed(),
            original.transactions());
        tampered.set(1, fake);

        assertThrows(Blockchain.InvalidChainException.class,
            () -> Blockchain.replayAndValidate(tampered));
    }
}
