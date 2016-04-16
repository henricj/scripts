#!/usr/local/bin/bash

# Stir the openssl ~/.rnd pool by doing many PFS TLS connections
# and hoping that at least some key exchanges are not observed.
# We write to /dev/random as well.  Unfortunately, on FreeBSD 10
# this is the same as writing to /dev/null (this is fixed in
# current/11 and wasn't borked before 10).  See the random_write()
# change here:
#    https://svnweb.freebsd.org/base/head/sys/dev/random/randomdev.c?r1=255379&r2=256377

if [ -z "${_stir_loaded}" ] ; then
_stir_loaded="yes"

set -o pipefail

. ./rng_pool.sh

_stir_with_scott()
{
   local scott_blob=` \
   { rng_generate_output 4 && dd if=/dev/random bs=256 count=1 2> /dev/null ; } \
   | ssh scott.private -C 2>/dev/null \
      'openssl rand -rand /dev/random:/dev/stdin 64 && \
       openssl rand -engine rdrand 32768 \
          | openssl dgst -sha512 -binary && \
       dd if=/dev/random bs=64 count=1' \
   | base64 -e \
`

   rng_stir ${scott_blob}
}

stir_initialize()
{
   if [ -z "${_stir_initialized}" ] ; then
      _stir_initialized="true"

      rng_initialize_pool

      _stir_with_scott
   fi

   rng_stir_with_external
}

stir_generate_entropy_files()
{
   if ! [ -d .entropy ] ; then
      mkdir .entropy/
   fi

   if ! stir_generate_output 2 \
         | openssl rand -rand /dev/stdin:/dev/random 1024 > .entropy/entropy.ssl.`date "+%s"` ; then
      echo >/dev/stderr "stir failed" ${PIPESTATUS[0]} ${PIPESTATUS[1]}
      exit 1
   fi

   stir_generate_output 4 > .entropy/entropy.raw.`date "+%s"` || exit 1
}

stir_clean_entropy_files()
{
   rm .entropy/entropy.*
}

stir_generate_output()
{
   local repeat count

   count=${1:-1}

   rng_update_keys

   { \
      for ((repeat = 0; repeat < ${count}; ++repeat)) ; do \
         dd if=/dev/random bs=64 count=1 2> /dev/null && \
         rng_generate_output 8 && \
         rng_generate_output 4 | openssl rand -rand /dev/random:/dev/stdin 64 2> /dev/null \
      ; done \
   ; } \
   | openssl aes-256-cbc -e -K ${key} -iv ${iv} -nopad \
   || exit 1

   rng_stir_with_external
}


stir_add_entropy()
{
   rng_update_keys

   local entropy=`echo ${1} | base64 -d | openssl aes-256-cbc -e -K ${key} -iv ${iv} | base64 -e`

   rng_stir ${entropy}

   rng_stir_with_external
}

fi

