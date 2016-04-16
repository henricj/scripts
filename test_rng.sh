#!/usr/local/bin/bash

set -o pipefail

. ./rng_pool.sh

rng_initialize_pool || exit 1

rng_generate_output 4 | hexdump -C || exit 1

echo pool length: ${#rng_pool} count: ${rng_count}

