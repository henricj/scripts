#!/usr/local/bin/bash

set -o pipefail

sudo -v

. ./stir.sh

stir_initialize || exit 1

if ! stir_generate_output 8 \
      | sudo dd of=/dev/random bs=16k ; then
   echo >/dev/stderr "stir failed" ${PIPESTATUS[0]} ${PIPESTATUS[1]}
   exit 1
fi

stir_generate_entropy_files || exit 1

sudo cp .entropy/entropy.* /var/db/entropy/

stir_clean_entropy_files

