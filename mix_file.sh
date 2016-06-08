#!/usr/local/bin/bash

set -o pipefail

set -e

. ./rng_pool.sh

mix_file()
{
   local repeat i

   for ((repeat = 0; repeat < 4; ++repeat)) ; do
      for ((i = 0; i < 8; ++i)) ; do
         rng_update_keys || exit 1

         local blob=$( \
            openssl aes-256-cbc -e -K ${key} -iv ${iv} < "${1}" \
            | openssl dgst -hmac "${BASHPID}-${stir}" -sha512 -binary \
            | base64 -e
         ) || exit 1

         rng_stir ${blob} || exit 1
         echo -n "f"
      done

      rng_stir_with_external || exit 1
   done

   echo
}

rng_initialize_pool || exit 1

date

mix_file "${1}"

date


