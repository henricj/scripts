#!/usr/local/bin/bash

# Stir the openssl ~/.rnd pool by doing many PFS TLS connections
# and hoping that at least some key exchanges are not observed.
# We write to /dev/random as well.  Unfortunately, on FreeBSD 10
# this is the same as writing to /dev/null (this is fixed in
# current/11 and wasn't borked before 10).  See the random_write()
# change here:
#    https://svnweb.freebsd.org/base/head/sys/dev/random/randomdev.c?r1=255379&r2=256377

if [ -z "${_rng_pool_loaded}" ]; then
_rng_pool_loaded="yes"

print_cipher()
{
   local cipher=$(awk '/Cipher +:/ { print $3 }')

   if [ ${#cipher} -eq 0 ] ; then
      return 1
   fi

   printf "TLS %s (%s)\n" ${1} ${cipher} >/dev/stderr
}

tls()
{
   openssl s_client -connect ${1}:443 -no_ssl2 -no_ssl3 -CAfile /usr/local/etc/ssl/cert.pem < /dev/null 2>/dev/null \
         | tee >( print_cipher ${1} ) \
      && return 0

   echo >/dev/stderr "${1} failed"

   exit 1
}

multi_tls()
{
   local pids idx sites=(${@})

#echo >/dev/stderr multi_tls sites "${sites[@]}" indexes "${!sites[@]}"

   local ret pid 

   for idx in "${!sites[@]}" ; do
      local site=${sites[${idx}]}

      tls ${site} | openssl dgst -hmac "${site}-${rng_hmac}" -sha512 -binary &
      
      ret=$?
      pid=$! 

      if [ ${ret} -ne 0 ] ; then
         echo >/dev/stderr "Unable to read" ${site}
         wait
         exit 1
      fi

      pids[${idx}]=${pid}
   done

#echo > /dev/stderr pids ${pids[@]} sites ${sites[@]}

   for idx in "${!sites[@]}" ; do
      local pid=${pids[${idx}]}
      local site=${sites[${idx}]}

      if [ -z ${pid+x} ] ; then
         echo >/dev/stderr worker for ${site} has no pid
         wait

         exit 1 
      fi

#echo >/dev/stderr waiting for ${site} pid ${pid}
      if ! wait ${pid} ; then
         echo >/dev/stderr worker for ${site} pid ${pid} failed
         wait

         exit 1
      fi
   done

   return 0
}

_rng_generate_block()
{
   #echo >/dev/stderr "${1}: ${rng_count}-$HOST-$$-`date -n`"

   { \
      echo ${rng} | base64 -d && \
      echo "${rng_raw}" && \
      echo ${rng_pool} | base64 -d ; \
   } \
   | openssl dgst -hmac "${1}: ${rng_count}-$HOST-$$-`date -n`" -sha512 -binary
}

_rng_generate()
{
   _rng_rekey || exit 1

   _rng_update || exit 1

   { \
      _rng_generate_block "generate" && \
      echo "${rng_raw}" && \
      echo ${rng_pool} | base64 -d ; \
   } \
   | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
   | openssl dgst -hmac ${rng_hmac} -sha512 -binary
}

_rng_update()
{
   ((rng_count++))

   rng=$( _rng_generate_block "rng" | base64 -e ) || exit 1

   ((rng_count++))
}

_rng_rekey()
{
   _rng_update || exit 1

   rng_hmac=$( \
      _rng_generate_block "hmac" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 64 2> /dev/null \
   ) || exit 1

   _rng_update || exit 1

   rng_key=$( \
      _rng_generate_block "key" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 32 2> /dev/null \
   ) || exit 1

   _rng_update || exit 1

   rng_iv=$( \
      _rng_generate_block "iv" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 16 2> /dev/null \
   )
}

# Stir the random pool (backtracking resistance)
rng_stir()
{
   _rng_rekey || exit 1

   rng_pool=$( \
      { echo ${1} | base64 -d ; echo ${rng_pool} | base64 -d ; } \
      | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
      | base64 -e) || exit 1

   # Prevent accidental reuse
   unset rng_key rng_iv || exit 1
  
   _rng_update || exit 1
 
   _rng_generate_block "stir" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 32 2>/dev/null >/dev/null
}

rng_sysctl_add_and_stir()
{
   local repeat

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   _rng_rekey || exit 1

   rng_pool=$( \
         { sysctl -ba | openssl dgst -hmac ${rng_hmac} -sha512 -binary \
            && echo ${rng_pool} | base64 -d ; } \
         | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
         | base64 -e )

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   _rng_rekey || exit 1
}

rng_stir_with_external()
{
   umask 077

   if [ ! -w .rng.pool ] ; then
      if [ -e .rng.pool ] ; then
         rm .rng.pool || exit 1
      fi
      openssl rand 3072 > .rng.pool 2> /dev/null || exit 1
   fi

   if [ -e .rng.pool.tmp ] ; then
      rm .rng.pool.tmp || exit 1
   fi

   local enc_iv enc_key hmac_key repeat digest

   for ((repeat = 0; repeat < 4; ++repeat)) ; do
      enc_iv=$(rng_generate 16) || exit 1
      enc_key=$(rng_generate 32) || exit 1

      openssl enc -aes-256-ctr -nosalt -K ${enc_key} -iv ${enc_iv} \
         -in .rng.pool -out .rng.pool.tmp \
         2> /dev/null \
      || exit 1

      enc_iv=$(rng_generate 16) || exit 1
      enc_key=$(rng_generate 32) || exit 1
      hmac_key=$(rng_generate 64) || exit 1

      digest=` \
         openssl aes-256-cbc -e -K ${enc_key} -iv ${enc_iv} -in .rng.pool.tmp \
         | openssl dgst -hmac ${hmac_key} -sha512 -binary \
         | base64 -e
      ` || exit 1

#echo >/dev/stderr digest: ${digest}

      rng_stir ${digest}

      enc_iv=$(rng_generate 16) || exit 1
      enc_key=$(rng_generate 32) || exit 1

      openssl enc -aes-256-ctr -nosalt -K ${enc_key} -iv ${enc_iv} \
         -in .rng.pool.tmp -out .rng.pool \
         2> /dev/null \
      || exit 1

   done

   rm .rng.pool.tmp
}

# Add entropy from given URLs
rng_add_tls()
{
   local pool code repeat retry

   for retry in {1..3} ; do
      _rng_rekey || exit 1

      # The TLS connection's master key is the important part
      pool=$( \
         { multi_tls "${@}" && echo ${rng_pool} | base64 -d ; } \
         | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
         | base64 -e )

      code=$?

      for ((repeat = 0; repeat < 16; ++repeat)) ; do
         rng_stir || exit 1
      done
      
      if [ ${code} -eq 0 ] ; then
         break
      fi

      sleep 3
      echo >/dev/stderr "Retrying"
   done

   if [ ${code} -ne 0 ] ; then
      echo >/dev/stderr "Pool update failed"
      exit 1
   fi

   rng_pool=${pool} 

   return 0
}

rng_add_multi_tls()
{
   local all=(${@})

   while [ ${#all[@]} -ne 0 ] ; do
      local batch=("${all[@]:0:9}")

      all=("${all[@]:9}")

      rng_add_tls "${batch[@]}"
   done
}

rng_generate()
{
   _rng_generate \
  | openssl rand -rand /dev/stdin:/dev/random -hex ${1} 2> /dev/null \
  || exit 1

  rng_stir || exit 1
}

rng_generate_binary()
{
   local ctr_iv=$(rng_generate 16) || exit 1
   local ctr_key=$(rng_generate 32) || exit 1

   _rng_generate \
  | openssl rand -rand /dev/stdin:/dev/random ${1} 2> /dev/null \
  | openssl enc -aes-256-ctr -nosalt -K ${ctr_key} -iv ${ctr_iv} 2> /dev/null \
  || exit 1

  rng_stir || exit 1
}

rng_initialize()
{
   local start_time=`date`

   local nist_raw random_raw anu_raw hotbits_raw

   nist_raw=`curl -s https://beacon.nist.gov/rest/record/last` || exit 1

#echo >/dev/stderr NIST ${#nist_raw} bytes

   random_raw=`curl -s "https://www.random.org/integers/?num=20&min=-1000000000&max=1000000000&col=1&base=16&format=plain&rnd=new"` || exit 1

#echo >/dev/stderr random ${#random_raw} bytes

   anu_raw=`curl -s "https://qrng.anu.edu.au/API/jsonI.php?length=8&type=hex16&size=16"` || exit 1

#echo >/dev/stderr anu ${#anu_raw} bytes

   hotbits_raw=`curl -s "https://www.fourmilab.ch/cgi-bin/Hotbits?nbytes=64&fmt=bin&npass=1&lpass=8&pwtype=3" | base64 -e` || exit 1

#echo >/dev/stderr hotbits ${#hotbits_raw} bytes

#echo >/dev/stderr nist_raw: ${nist_raw}
#echo >/dev/stderr random_raw: ${random_raw}
#echo >/dev/stderr anu_raw: ${anu_raw}
#echo >/dev/stderr hotbits_raw: ${hotbits_raw}

   local uname=`uname -a`

   rng_raw="${start_time}
$$
${uname}
${nist_raw}
${random_raw}
${anu_raw}
${hotbits_raw}"

#echo >/dev/stderr rng_raw: "${rng_raw}"

# Note well:  All of this function's sources above this comment are
# public.  They are meant to make sure that each run is unique and
# uncorrelated with other runs on this or any other system.

   rng_pool=$(echo "${rng_raw}" | base64 -e) || exit 1

# The sysctl should also be considered public information.  However, it
# is unlikely that two runs will give the same results.

   rng_sysctl_add_and_stir || exit 1

# At this point, rng_pool should be universally unique.  Now we'll try to
# fetch something entropy-ish.  The whole premise is that for at least some
# runs, at least one TLS connection is not observed.

   rng_stir_with_external || exit 1

   local allSites

   readarray -t allSites < <(sort -uR sites | head -30) || exit 1

   if [ -e sites.local ] ; then
      readarray -t localSites < <(sort -uR sites.local) || exit 1
      if [ ${#localSites[@]} -ne 0 ] ; then
         rng_add_multi_tls "${localSites[@]}"
      fi
   fi

   rng_stir_with_external || exit 1

   local split=$(( 2 * ${#allSites[*]} / 3 ))

   sites=("${allSites[@]:${split}}")

   local firstSites=("${allSites[@]:0:${split}}")

   rng_add_multi_tls "${firstSites[@]}"

   rng_stir_with_external || exit 1

#echo >/dev/stderr pool length: ${#rng_pool} count: ${rng_count}
}

rng_update_keys()
{
   iv=$(rng_generate 16) || exit 1
   key=$(rng_generate 32) || exit 1
   stir=$(rng_generate 64) || exit 1
}

generate_output()
{
   local repeat

   for ((repeat = 0; repeat < ${1} ; ++repeat)) ; do
      rng_generate_binary 8 || exit 1
   done
}

rng_initialize_pool()
{
   rng_initialize || exit 1

   rng_sysctl_add_and_stir || exit 1

   # Read the local sites again (if we have any)
   if [ ${#localSites[@]} -ne 0 ] ; then
      rng_add_multi_tls "${localSites[@]}" || exit 1
   fi

   rng_add_multi_tls "${sites[@]}" || exit 1

   rng_sysctl_add_and_stir || exit 1
}

rng_generate_output()
{
   local output_iv=$(rng_generate 16) || exit 1
   local output_key=$(rng_generate 32) || exit 1

   local ctr_iv=$(rng_generate 16) || exit 1
   local ctr_key=$(rng_generate 32) || exit 1

   generate_output ${1} \
   | openssl enc -aes-256-ctr -nosalt -K ${ctr_key} -iv ${ctr_iv} 2> /dev/null \
   | openssl aes-256-cbc -e -K ${output_key} -iv ${output_iv} \
   || exit 1
}

fi
