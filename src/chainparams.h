// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <memory>
#include <vector>

struct CDNSSeedData {
    std::string name, host;
    bool supportsServiceBitsFiltering;
    CDNSSeedData(const std::string &strName, const std::string &strHost,
                 bool supportsServiceBitsFilteringIn = false)
        : name(strName), host(strHost),
          supportsServiceBitsFiltering(supportsServiceBitsFilteringIn) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
};

struct ChainTxData {
    int64_t nTime;
    int64_t nTxCount;
    double dTxRate;
};

// Contains defaults for block size related parameters. 
// Defaults are used changed based on activation time

struct DefaultBlockSizeParams {
    int64_t blockSizeActivationTime;
    uint64_t maxBlockSizeBefore;
    uint64_t maxBlockSizeAfter;
    uint64_t maxGeneratedBlockSizeBefore;
    uint64_t maxGeneratedBlockSizeAfter;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams {
public:
   #ifdef ENABLE_VID
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        ZCPAYMENT_ADDRRESS,
        ZCSPENDING_KEY,
        ZCVIEWING_KEY,

        MAX_BASE58_TYPES
    };

    enum Bech32Type {
        SAPLING_PAYMENT_ADDRESS,
        SAPLING_FULL_VIEWING_KEY,
        SAPLING_INCOMING_VIEWING_KEY,
        SAPLING_EXTENDED_SPEND_KEY,

        WITNESS_KEY,

        MAX_BECH32_TYPES
    };
    
    const std::vector<unsigned char>& Base58BTCPrefix(Base58Type type) const
    {
        return base58BTCPrefixes[type];
    }
    const std::string& Bech32HRP(Bech32Type type) const
    {
        return bech32HRPs[type];
    }
private:
    std::vector<unsigned char> base58BTCPrefixes[MAX_BASE58_TYPES];
    std::string bech32HRPs[MAX_BECH32_TYPES];

public:
#else
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };
#endif


    const Consensus::Params &GetConsensus() const { return consensus; }
    const CMessageHeader::MessageMagic &DiskMagic() const { return diskMagic; }
    const CMessageHeader::MessageMagic &NetMagic() const { return netMagic; }
    int GetDefaultPort() const { return nDefaultPort; }

    const CBlock &GenesisBlock() const { return genesis; }
    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /**
     * Make miner stop after a block is found. In RPC, don't return until
     * nGenProcLimit blocks are generated.
     */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    const std::vector<CDNSSeedData> &DNSSeeds() const { return vSeeds; }
    const std::vector<uint8_t> &Base58Prefix(Base58Type type) const {
        return base58Prefixes[type];
    }
    const std::string &CashAddrPrefix() const { return cashaddrPrefix; }
    const std::vector<SeedSpec6> &FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData &Checkpoints() const { return checkpointData; }
    const ChainTxData &TxData() const { return chainTxData; }
    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                              int64_t nTimeout);
    const DefaultBlockSizeParams &GetDefaultBlockSizeParams() const { return defaultBlockSizeParams; }

protected:
    friend void ResetNetMagic(CChainParams& chainParam, const std::string& hexcode);
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageMagic diskMagic;
    CMessageHeader::MessageMagic netMagic;
    int nDefaultPort;
    uint64_t nPruneAfterHeight;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<uint8_t> base58Prefixes[MAX_BASE58_TYPES];
    std::string cashaddrPrefix;
    std::string strNetworkID;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    CCheckpointData checkpointData;
    ChainTxData chainTxData;
    DefaultBlockSizeParams defaultBlockSizeParams;
};

/**
 * Convert hex string into CMessageHeader::MessageMagic
 */
bool HexToArray(const std::string& hexstring, CMessageHeader::MessageMagic& array);

/**
 * Creates and returns a std::unique_ptr<CChainParams> of the chosen chain.
 * @returns a CChainParams* of the chosen chain.
 * @throws a std::runtime_error if the chain is not supported.
 */
std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string &chain);

/**
 * Allows modifying the BIP9 regtest parameters.
 */
void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                          int64_t nTimeout);

#endif // BITCOIN_CHAINPARAMS_H
