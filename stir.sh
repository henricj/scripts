#!/usr/local/bin/bash

set -o pipefail

tls()
{
   echo -n >/dev/stderr Connect to ${1}

   openssl s_client -connect ${1}:443 -no_ssl2 -no_ssl3 -CAfile /usr/local/etc/ssl/cert.pem < /dev/null 2>/dev/null \
         | tee >(awk '/Cipher +:/ { print " (" $3 ")" }' >/dev/stderr ) \
      && return 0

   echo >/dev/stderr " failed"

   exit 1
}

_rng_generate_block()
{
   { \
      echo ${rng} && \
      echo ${rng_raw} && \
      echo ${rng_pool} | base64 -d ; \
   } \
   | openssl dgst -hmac "${1}: $HOST-$$-${rng_count}-`date -n`" -sha512 -binary
}

_rng_generate()
{
   _rng_rekey

   _rng_update

   { \
      _rng_generate_block "generate" && \
      echo ${rng_raw} && \
      echo ${rng_pool} | base64 -d ; \
   } \
   | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
   | openssl dgst -sha512 -binary \
   | openssl rand -rand /dev/stdin:/dev/random -hex ${1} 2> /dev/null
}

_rng_update()
{
   if [ -z "${rng_count}" ] ; then
      rng_count=1
   else
      ((rng_count++))
   fi

   rng=$( _rng_generate_block "rng" )
}

_rng_rekey()
{
   _rng_update

   rng_key=$( \
      _rng_generate_block "key" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 32 2> /dev/null \
   )

   _rng_update

   rng_iv=$( \
      _rng_generate_block "iv" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 16 2> /dev/null \
   )
}

# Stir the random pool (backtracking resistance)
rng_stir()
{
   _rng_rekey

   rng_pool=$( \
      { echo ${rng_pool} | base64 -d ; } \
      | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
      | base64 -e)

   # Prevent accidental reuse
   unset rng_key rng_iv
  
   _rng_update
 
   _rng_generate_block "stir" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 32 2>/dev/null >/dev/null
}

# Add entropy from given URL
rng_add_tls()
{
   _rng_rekey || return 1

   # The TLS connection's master key is the important part
   rng_pool=$( \
      { echo ${rng_pool} | base64 -d && tls ${1} ; } \
      | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
      | base64 -e) \
   || return 1

   # Prevent accidental reuse
   unset rng_key rng_iv
      
   rng_stir
}

rng_generate()
{
   _rng_generate ${1} || return 1

  rng_stir
}

rng_initialize()
{
   nist_raw=`curl -s https://beacon.nist.gov/rest/record/last` || exit 1

#echo >/dev/stderr nist_raw: ${nist_raw}

   random_raw=`curl -s "https://www.random.org/integers/?num=20&min=-1000000000&max=1000000000&col=1&base=16&format=plain&rnd=new"` || exit 1

#echo >/dev/stderr random_raw: ${random_raw}

   anu_raw=`curl -s "https://qrng.anu.edu.au/API/jsonI.php?length=8&type=hex16&size=16"` || exit 1

#echo >/dev/stderr anu_raw: ${anu_raw}

   rng_raw=${nist_raw}${random_raw}${anu_raw}

   rng_pool=$(echo ${rng_raw} | base64 -e)

   rng_stir || exit 1

   rng_add_tls www.yahoo.com
   rng_add_tls www.eff.org
   rng_add_tls www.amazon.com
   rng_add_tls www.microsoft.com
   rng_add_tls www.linkedin.com
   rng_add_tls www.startpage.com
   rng_add_tls www.twitter.com
   rng_add_tls www.facebook.com
   rng_add_tls google.com

   rng_stir || exit 1

#echo >/dev/stderr pool length: ${#rng_pool}
}

rng_tls()
{
   rng_keys || return 1

   rng_update || return 1

   keyed_rng_tls ${1} ${2} ${rng_key} ${rng_iv}
}

keyed_rng_tls()
{
   rng_update || return 1

   { \
      dd if=/dev/random bs=256 count=1 2>/dev/null && \
      echo ${rng} && \
      tls ${1} ; \
   } \
         | openssl aes-256-cbc -K ${3} -iv ${4} \
         | openssl rand -rand /dev/stdin:/dev/random -hex ${2} 2> /dev/null
}

get_keys()
{
   iv=$(rng_generate 16) || return 1

   key=$(rng_generate 32) || return 1

   stir=$(rng_generate 64) || return 1

   return 0
}

rng_initialize

if ! get_keys ; then
   echo >/dev/stderr get_keys failed
   exit 1
fi

#echo >/dev/stderr iv is $iv
#echo >/dev/stderr key is $key
#echo >/dev/stderr stir is $stir

rng_add_tls www.aclu.org || exit 1
rng_add_tls www.schneier.com || exit 1

rng_stir || exit 1

{ \
   dd if=/dev/random bs=64 count=1 2> /dev/null && \
   rng_generate 64 && \
   rng_generate 64 && \
   rng_generate 64 && \
   { echo ${stir} && dd if=/dev/random bs=256 count=1 2> /dev/null ; } \
   | ssh scott.private -C \
      'openssl rand -rand /dev/random:/dev/stdin 64 && \
       openssl rand -engine rdrand 32768 \
          | openssl dgst -sha512 -binary && \
       dd if=/dev/random bs=64 count=1' \
; } \
| openssl aes-256-cbc -e -K ${key} -iv ${iv}
