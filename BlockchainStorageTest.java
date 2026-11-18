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
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BlockchainStorageTest {

    @TempDir Path tempDir;

    private static Blockchain chainWithMinedBlock(Wallet miner) {
        Transaction cb = Transaction.coinbase(miner.address(), Blockchain.SUBSIDY);
        Block genesis = Block.seal(Block.ZERO_HASH, 0L, 0, 0, 0, List.of(cb));
        Blockchain bc = new Blockchain();
        bc.addGenesis(genesis);

        Block template = Block.seal(
            genesis.hash(), 1L, 1, 0, 0,
            List.of(Transaction.coinbase(miner.address(), Blockchain.SUBSIDY)));
        MiningEngine.MiningResult m = MiningEngine.mineDeterministic(template, 10_000);
        assertTrue(m.success());
        assertTrue(bc.addBlock(m.mined()).accepted());
        return bc;
    }

    @Test void roundTripPreservesChainAndBalance() throws Exception {
        Wallet miner = new Wallet();
        Blockchain bc = chainWithMinedBlock(miner);

        BlockchainStorage storage = new BlockchainStorage(tempDir.toString());
        storage.save(bc);

        Blockchain reloaded = storage.load();
        assertEquals(bc.height(), reloaded.height());
        assertEquals(bc.latest().hash(), reloaded.latest().hash());
        assertEquals(bc.balanceOf(miner.address()), reloaded.balanceOf(miner.address()));
    }

    @Test void missingFileThrowsClearError() throws Exception {
        BlockchainStorage storage = new BlockchainStorage(tempDir.toString());
        assertFalse(storage.exists());
        IOException e = assertThrows(IOException.class, storage::load);
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test void tamperedFileIsRejectedAtLoad() throws Exception {
        Wallet miner = new Wallet();
        Blockchain bc = chainWithMinedBlock(miner);
        BlockchainStorage storage = new BlockchainStorage(tempDir.toString());
        storage.save(bc);

        // Flip one byte in the middle of the file.
        Path chainFile = tempDir.resolve("chain.bin");
        byte[] bytes = Files.readAllBytes(chainFile);
        bytes[bytes.length / 2] ^= 0x01;
        Files.write(chainFile, bytes);

        assertThrows(IOException.class, storage::load);
    }

    @Test void badMagicIsRejected() throws Exception {
        BlockchainStorage storage = new BlockchainStorage(tempDir.toString());
        Path chainFile = tempDir.resolve("chain.bin");
        Files.write(chainFile, "not a chain file at all!!!!!".getBytes());

        assertThrows(IOException.class, storage::load);
    }

    @Test void saveIsAtomicAcrossOverwrites() throws Exception {
        Wallet miner = new Wallet();
        Blockchain bc = chainWithMinedBlock(miner);
        BlockchainStorage storage = new BlockchainStorage(tempDir.toString());

        storage.save(bc);
        Blockchain firstLoad = storage.load();

        // Save again (same chain) — file must be replaced atomically.
        storage.save(bc);
        Blockchain secondLoad = storage.load();

        assertEquals(firstLoad.latest().hash(), secondLoad.latest().hash());
    }

    @Test void walletRoundTrip() throws Exception {
        WalletStorage ws = new WalletStorage(tempDir.resolve("wallet.bin").toString());
        Wallet w = new Wallet();
        ws.save(w);

        Wallet reloaded = ws.load();
        assertEquals(w.address(), reloaded.address());
        byte[] msg = "prove it".getBytes();
        assertTrue(Wallet.verify(reloaded.publicKeyBytes(), msg, reloaded.sign(msg)));
    }
}
