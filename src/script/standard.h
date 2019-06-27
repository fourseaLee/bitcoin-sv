// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include "script/interpreter.h"
#include "uint256.h"

#include <boost/variant.hpp>

#include <cstdint>

static const bool DEFAULT_ACCEPT_DATACARRIER = true;

class CKeyID;
class CScript;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160 {
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript &in);
    CScriptID(const uint160 &in) : uint160(in) {}
};

//!< bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
static const uint64_t DEFAULT_DATA_CARRIER_SIZE = 100000;
extern bool fAcceptDatacarrier;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static const uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC |
    SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL;

enum txnouttype {
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
};

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) {
        return true;
    }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) {
        return true;
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
#ifdef ENABLE_VID
    class WitnessV0ScriptHash : public uint256 {
     public:  
       WitnessV0ScriptHash() : uint256() {}
       WitnessV0ScriptHash(const uint256& hash) : uint256(hash) {}
       WitnessV0ScriptHash(const CScript& script);
    };

    class WitnessV0KeyHash : public uint160 {
    public:
        WitnessV0KeyHash() : uint160() {}
        WitnessV0KeyHash(const uint160& hash) : uint160(hash) {}
    };


//! CTxDestination subtype to encode any future Witness version
    class WitnessUnknown {
    public:
        unsigned int version;
        unsigned int length;
        unsigned char program[40];

        friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2)
        {
            if (w1.version != w2.version) return false;
            if (w1.length != w2.length) return false;
            return std::equal(w1.program, w1.program + w1.length, w2.program);
        }

        friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2)
        {
            if (w1.version < w2.version) return true;
            if (w1.version > w2.version) return false;
            if (w1.length < w2.length) return true;
            if (w1.length > w2.length) return false;
            return std::lexicographical_compare(w1.program, w1.program + w1.length, w2.program, w2.program + w2.length);
        }

        ADD_SERIALIZE_METHODS
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(version);
            READWRITE(length);
            for (int i = 0; i < 40; i++) {
                READWRITE(program[i]);
            }
        }
    };
    
    typedef boost::variant<CNoDestination, CKeyID, CScriptID, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessUnknown> CTxDestination;
#else
    typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;
#endif

const char *GetTxnOutputType(txnouttype t);
bool IsValidDestination(const CTxDestination &dest);

bool Solver(const CScript &scriptPubKey, txnouttype &typeRet,
            std::vector<std::vector<uint8_t>> &vSolutionsRet);
bool ExtractDestination(const CScript &scriptPubKey,
                        CTxDestination &addressRet);
bool ExtractDestinations(const CScript &scriptPubKey, txnouttype &typeRet,
        std::vector<CTxDestination> &addressRet,
        int &nRequiredRet);

CScript GetScriptForDestination(const CTxDestination &dest);
CScript GetScriptForRawPubKey(const CPubKey &pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);

#endif // BITCOIN_SCRIPT_STANDARD_H
