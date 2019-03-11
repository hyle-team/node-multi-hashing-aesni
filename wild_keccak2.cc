// Copyright (c) 2014-2018 Zano Project
// Copyright (c) 2014-2018 Zano Project
// Copyright (c) 2014-2018 The Louisdor Project
// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// keccak.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// A baseline Keccak (3rd round) implementation.

// Memory-hard extension of keccak for PoW
// Copyright (c) 2014 The Boolberry developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wild_keccak2.h"
#include "crypto/wild_keccak2.h"

#include <iostream>

#define CURRENCY_SCRATCHPAD_BASE_SIZE           167 //count in crypto::hash, to get size in bytes x32
#define CURRENCY_SCRATCHPAD_REBUILD_INTERVAL    720 //once a day if block goes once in 2 minute

void wildkeccak2_hash(const char* input, uint32_t input_len, const char* scratchpad, uint64_t spad_length, char* output) {
    std::vector<crypto::hash> spad;
    for (uint64_t i = 0; i < spad_length; i+=HASH_SIZE) {
       crypto::hash elem = *(crypto::hash*) &scratchpad[i];
       spad.push_back(elem);
    }
    crypto::get_wild_keccak2(std::string(input, input_len), *((crypto::hash*)output), spad);
}

uint64_t get_scratchpad_last_update_rebuild_height(uint64_t h) {
    return h - (h%CURRENCY_SCRATCHPAD_REBUILD_INTERVAL);
}

uint64_t get_scratchpad_size_for_height(uint64_t h) {
    //let's have ~256MB/year if block interval is 2 minutes
    return CURRENCY_SCRATCHPAD_BASE_SIZE + get_scratchpad_last_update_rebuild_height(h)*32;
}

bool wildkeccak2_generate_scratchpad(const char* seed_data, char* result_data, uint64_t height) {
    crypto::hash seed = *(crypto::hash*) seed_data;
    std::vector<crypto::hash> result;
    uint64_t len = get_scratchpad_size_for_height(height);
    crypto::generate_scratchpad(seed, result, len);
    memcpy(result_data, result.data(), len);
}

uint64_t wildkeccak2_scratchpad_size(uint64_t h) {
    return get_scratchpad_size_for_height(h);
}