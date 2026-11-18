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

class TransactionAndBlockTest {

    // ── Transaction: txId is content-derived ─────────────────────────────

    @Test void coinbaseTxIdIsDeterministic() {
        Transaction a = Transaction.coinbase("Maddr", 50L);
        Transaction b = Transaction.coinbase("Maddr", 50L);
        assertEquals(a.txId(), b.txId());
    }

    @Test void changingOutputAmountChangesTxId() {
        Transaction a = Transaction.coinbase("Maddr", 50L);
        Transaction b = Transaction.coinbase("Maddr", 51L);
        assertNotEquals(a.txId(), b.txId());
    }

    @Test void changingAddressChangesTxId() {
        Transaction a = Transaction.coinbase("MaddrA", 50L);
        Transaction b = Transaction.coinbase("MaddrB", 50L);
        assertNotEquals(a.txId(), b.txId());
    }

    @Test void txIdIs64LowercaseHex() {
        String id = Transaction.coinbase("Maddr", 50L).txId();
        assertEquals(64, id.length());
        assertTrue(id.matches("[0-9a-f]{64}"), id);
    }

    @Test void regularTransactionRequiresInputs() {
        assertThrows(IllegalArgumentException.class,
            () -> Transaction.create(List.of(), List.of(new Transaction.Output(1, "M")), 0));
    }

    @Test void outputRejectsNonPositiveAmount() {
        assertThrows(IllegalArgumentException.class,
            () -> new Transaction.Output(0, "M"));
        assertThrows(IllegalArgumentException.class,
            () -> new Transaction.Output(-1, "M"));
    }

    @Test void canonicalBytesAreStable() {
        Transaction t = Transaction.coinbase("Maddr", 50L);
        assertArrayEquals(t.canonicalBytes(), t.canonicalBytes());
    }

    // ── Merkle root ──────────────────────────────────────────────────────

    @Test void emptyBlockMerkleRootIsZeros() {
        assertEquals(Block.ZERO_HASH, Block.computeMerkleRoot(List.of()));
    }

    @Test void singleTxMerkleRootEqualsTxId() {
        Transaction t = Transaction.coinbase("Maddr", 50L);
        assertEquals(t.txId(), Block.computeMerkleRoot(List.of(t)));
    }

    @Test void twoTxMerkleRootIsPairHash() {
        Transaction a = Transaction.coinbase("A", 10L);
        Transaction b = Transaction.coinbase("B", 20L);
        byte[] pair = new byte[64];
        System.arraycopy(CryptoUtils.hexToBytes(a.txId()), 0, pair, 0, 32);
        System.arraycopy(CryptoUtils.hexToBytes(b.txId()), 0, pair, 32, 32);
        String expected = CryptoUtils.bytesToHex(CryptoUtils.doubleSha256(pair));
        assertEquals(expected, Block.computeMerkleRoot(List.of(a, b)));
    }

    @Test void oddTxCountDuplicatesLastHash() {
        Transaction a = Transaction.coinbase("A", 10L);
        Transaction b = Transaction.coinbase("B", 20L);
        Transaction c = Transaction.coinbase("C", 30L);

        // 3 leaves → level1: [H(a,b), H(c,c)] → level2: H(H(a,b), H(c,c))
        byte[] ab = concat(CryptoUtils.hexToBytes(a.txId()), CryptoUtils.hexToBytes(b.txId()));
        byte[] cc = concat(CryptoUtils.hexToBytes(c.txId()), CryptoUtils.hexToBytes(c.txId()));
        byte[] root = concat(CryptoUtils.doubleSha256(ab), CryptoUtils.doubleSha256(cc));
        String expected = CryptoUtils.bytesToHex(CryptoUtils.doubleSha256(root));

        assertEquals(expected, Block.computeMerkleRoot(List.of(a, b, c)));
    }

    // ── Block: hash commits to contents ──────────────────────────────────

    @Test void changingATransactionChangesTheBlockHash() {
        Block withA = Block.seal(Block.ZERO_HASH, 0L, 2, 0, 0,
                List.of(Transaction.coinbase("A", 10L)));
        Block withB = Block.seal(Block.ZERO_HASH, 0L, 2, 0, 0,
                List.of(Transaction.coinbase("B", 10L)));
        assertNotEquals(withA.hash(), withB.hash());
        assertNotEquals(withA.merkleRoot(), withB.merkleRoot());
    }

    @Test void sealRejectsInvalidPreviousHash() {
        assertThrows(IllegalArgumentException.class,
            () -> Block.seal("nothex", 0L, 1, 0, 0, List.of()));
    }

    @Test void sealRejectsImpossibleDifficulty() {
        assertThrows(IllegalArgumentException.class,
            () -> Block.seal(Block.ZERO_HASH, 0L, 65, 0, 0, List.of()));
    }

    @Test void headerIsFixed96Bytes() {
        Block b = Block.seal(Block.ZERO_HASH, 0L, 1, 0, 0, List.of());
        assertEquals(96, b.serializeHeader().length);
    }

    @Test void hashMatchesHeaderRoundTrips() {
        Block b = Block.seal(Block.ZERO_HASH, 123L, 1, 7, 42, List.of());
        assertTrue(b.hashMatchesHeader());
    }

    @Test void withNonceChangesHash() {
        Block b = Block.seal(Block.ZERO_HASH, 0L, 1, 0, 0, List.of());
        Block b2 = b.withNonceAndSeed(1L, 0);
        assertNotEquals(b.hash(), b2.hash());
    }

    @Test void meetsDifficultyRespectsTarget() {
        // Keep trying nonces/seeds until we find a hash with 1 leading zero.
        Block b = Block.seal(Block.ZERO_HASH, 0L, 1, 0, 0, List.of());
        long nonce = 0;
        while (!b.meetsDifficulty() && nonce < 10_000) {
            nonce++;
            b = b.withNonceAndSeed(nonce, 0);
        }
        assertTrue(b.meetsDifficulty(), "should find a 1-zero hash quickly");
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}