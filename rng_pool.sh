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

   if [[ ${cipher} == DHE-* ]] || [[ ${cipher} == ECDHE-* ]] ; then
      echo -n . > /dev/stderr
   else
      printf "TLS %s (%s)\n" ${1} ${cipher} >/dev/stderr
   fi

   return 0
}

tls()
{
   timeout 10 openssl s_client -connect ${1}:443 -no_ssl2 -no_ssl3 -CAfile /usr/local/etc/ssl/cert.pem < /dev/null 2>/dev/null \
         | tee >( print_cipher ${1} ) \
      && return 0

   echo >/dev/stderr "${1} failed"

   exit 1
}

multi_tls()
{
   local pids idx ret pid failures=0 sites=(${@})

#echo >/dev/stderr multi_tls sites "${sites[@]}" # indexes "${!sites[@]}"

   rng_stir || exit 1

   _rng_rekey || exit 1

   for idx in "${!sites[@]}" ; do
      local site=${sites[${idx}]}

      _rng_update || exit 1

      local site_hmac=$( _rng_generate_key ${site} ) || exit 1

      tls ${site} | openssl dgst -hmac "${site}-${site_hmac}-${BASHPID}" -sha512 -binary &
      
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

         ((++failures))

         if [ ${failures} -ge $(( ${#sites[@]} / 4 + 1 )) ]; then      
            echo >/dev/stderr Giving up
            wait

            exit 1
         fi
      fi
   done

   echo >/dev/stderr

   return 0
}

_rng_bin_to_hex()
{
   if [ -z ${1+x} ] ; then
      hexdump -e '4/1 "%02.2x"' || exit 1
   else
      hexdump -e '4/1 "%02.2x"' -n ${1} || exit 1
   fi
}

_rng_generate_block()
{
  local hmac_string="${1}: ${rng_count}-$HOST-${BASHPID}-`date`"

#echo >/dev/stderr "${hmac_string}"

   { \
      echo "${rng}" | base64 -d && \
      echo -n "${2}" && \
      echo "${rng_raw}" && \
      echo "${rng_pool}" | base64 -d ; \
   } \
   | openssl dgst -hmac "${hmac_string}" -sha512 -binary
}

_rng_generate64()
{
   _rng_rekey || exit 1

   _rng_update || exit 1

   { \
      _rng_generate_block "generate" && \
      echo -n "${rng_raw}" && \
      echo "${rng_pool}" | base64 -d ; \
   } \
   | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} -nopad \
   | openssl dgst -hmac ${rng_hmac} -sha512 -binary \
   || exit 1
}

_rng_generate()
{
   local count

   for ((count = ${1}; count >= 64; count -= 64)) ; do
      _rng_generate64 || exit 1
   done

   if [ ${count} -gt 0 ] ; then
      _rng_generate64 | dd bs=${count} count=1 2>/dev/null || exit 1
   fi 
}

_rng_update()
{
   ((rng_count++))

   rng=$( _rng_generate_block "rng" | base64 -e ) || exit 1

   ((rng_count++))
}

_rng_generate_key()
{
   if [ -z ${1+x} ] ; then
      echo > /dev/stderr "_rng_generate_key() requires an argument"
      exit 1
   fi

   _rng_generate_block ${1} ${3} | _rng_bin_to_hex ${2} || exit 1
}

_rng_rekey()
{
   _rng_update || exit 1

   rng_hmac=$( _rng_generate_key "hmac" 64 ${rng_hmac} ) || exit 1

   _rng_update || exit 1

   rng_key=$( _rng_generate_key "key" 32 ${rng_key} ) || exit 1

   _rng_update || exit 1

   rng_iv=$( _rng_generate_key "iv" 16 ${rng_iv} ) || exit 1

   _rng_update || exit 1
}

_rng_rekey_stir()
{
   _rng_update || exit 1

   rng_stir_key=$( _rng_generate_key "stir_key" 32 ${rng_stir_key} ) || exit 1

   _rng_update || exit 1

   rng_stir_iv=$( _rng_generate_key "stir_iv" 16 ${rng_stir_iv} ) || exit 1
}

_rng_stir_kernel()
{
{   # The check for 141 is to ignore the SIGPIPE from the dd closing
   # the pipe before the base64 is done
   {
      { echo -n "${1}" || test $? -eq 141 ; } | { base64 -d || test $? -eq 141 ; } | dd obs=16 conv=osync 2> /dev/null ;
      { echo -n "${rng_pool}" || test $? -eq 141 ; } | { base64 -d || test $? -eq 141 ; } | dd ibs=331 skip=1 obs=4096 2>/dev/null &&
      { echo -n "${rng_pool}" || test $? -eq 141 ; } | { base64 -d || test $? -eq 141 ; } | dd ibs=331 count=1 2>/dev/null ;
   } \
   | openssl aes-256-ctr -e -K ${rng_stir_key} -iv ${rng_stir_iv} \
   | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} -nopad \
   | base64 -e ; } \
   || test $? -eq 141 \
   || exit 1
}


# Stir the random pool (backtracking resistance)
rng_stir()
{
   _rng_rekey_stir || exit 1

   _rng_rekey || exit 1

   rng_pool=$( _rng_stir_kernel ${1} ) || exit 1

   # Prevent accidental reuse
   _rng_rekey || exit 1
}

rng_sysctl_add_and_stir()
{
   local repeat

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   _rng_rekey_stir || exit 1

   _rng_rekey || exit 1

   rng_pool=$( \
         { \
            sysctl -ba | openssl dgst -hmac ${rng_hmac} -sha512 -binary && \
            echo -n "${rng_pool}" | base64 -d | dd ibs=113 skip=1 obs=4096 2>/dev/null && \
            { echo -n "${rng_pool}" || test $? -eq 141 ; } | { base64 -d || test $? -eq 141 ; } | dd ibs=113 count=1 2>/dev/null ; \
         } \
         | openssl aes-256-ctr -e -K ${rng_stir_key} -iv ${rng_stir_iv} \
         | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} -nopad \
         | base64 -e )

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   _rng_rekey || exit 1

   echo -n S
}

rng_stir_with_external()
{
   umask 077

   local repeat

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   if [ ! -w .rng.pool -o ! -s .rng.pool ] ; then
      if [ -e .rng.pool ] ; then
         rm .rng.pool || exit 1
      fi

      rng_generate_binary 256 \
      | openssl rand -rand /dev/stdin:/dev/random 3072 > .rng.pool 2> /dev/null \
      || exit 1
   fi

   if [ -e .rng.pool.tmp ] ; then
      rm .rng.pool.tmp || exit 1
   fi

   local ctr_iv ctr_key cbc_iv cbc_key hmac_key repeat digest

   for ((repeat = 0; repeat < 4; ++repeat)) ; do
      _rng_rekey || exit 1
      ctr_iv=$(rng_generate 16) || exit 1
      _rng_rekey || exit 1
      ctr_key=$(rng_generate 32) || exit 1
      _rng_rekey || exit 1
      cbc_iv=$(rng_generate 16) || exit 1
      _rng_rekey || exit 1
      cbc_key=$(rng_generate 32) || exit 1

      { \
         dd if=.rng.pool ibs=2011 skip=1 obs=4096 2>/dev/null && \
         dd if=.rng.pool ibs=2011 count=1 2>/dev/null \
      ; } \
      | openssl enc -aes-256-ctr -K ${ctr_key} -iv ${ctr_iv} \
      | openssl enc -aes-256-cbc -nopad -K ${cbc_key} -iv ${cbc_iv} -out .rng.pool.tmp \
         2> /dev/null \
      || exit 1

      rng_stir || exit 1

      _rng_rekey || exit 1
      cbc_iv=$(rng_generate 16) || exit 1
      _rng_rekey || exit 1
      cbc_key=$(rng_generate 32) || exit 1
      _rng_rekey || exit 1
      hmac_key=$(rng_generate 64) || exit 1

      rng_stir || exit 1

      digest=` \
         { rng_generate_binary 64 > /dev/random && \
           dd if=/dev/random bs=256 count=1 2>/dev/null && \
           rng_generate_binary 64 | openssl rand -rand /dev/stdin:/dev/random 256 2>/dev/null && \
           openssl aes-256-cbc -e -K ${cbc_key} -iv ${cbc_iv} -in .rng.pool.tmp ; } \
         | openssl dgst -hmac ${hmac_key} -sha512 -binary \
         | base64 -e \
      ` || exit 1

#echo >/dev/stderr digest: ${digest}

      rng_stir ${digest} || exit 1

      _rng_rekey || exit 1
      ctr_iv=$(rng_generate 16) || exit 1
      _rng_rekey || exit 1
      ctr_key=$(rng_generate 32) || exit 1
      _rng_rekey || exit 1
      cbc_iv=$(rng_generate 16) || exit 1
      _rng_rekey || exit 1
      cbc_key=$(rng_generate 32) || exit 1

      { \
         dd if=.rng.pool.tmp ibs=1031 skip=1 obs=4096 2>/dev/null && \
         dd if=.rng.pool.tmp ibs=1031 count=1 2>/dev/null \
      ; } \
      | openssl enc -aes-256-ctr -K ${ctr_key} -iv ${ctr_iv} -nopad \
      | openssl enc -aes-256-cbc -nopad -K ${cbc_key} -iv ${cbc_iv} -out .rng.pool \
         2> /dev/null \
      || exit 1

   done

   rm .rng.pool.tmp

   for ((repeat = 0; repeat < 100; ++repeat)) ; do
      rng_stir || exit 1
   done

   echo -n E
}

# Add entropy from given URLs
rng_add_tls()
{
   local pool code repeat retry

   for retry in {1..3} ; do
      rng_stir || exit 1

      # The TLS connection's master key is the important part
      pool=$( multi_tls "${@}" | base64 -e )

      code=$?
      
      if [ ${code} -eq 0 ] ; then
         break
      fi

      sleep 3
      echo >/dev/stderr "Retrying"
   done

   if [ ${code} -ne 0 ] ; then
      echo >/dev/stderr "Pool update failed"
      return 1
   fi

   rng_stir ${pool}

   return 0
}

_rng_add_multi_tls()
{
   local all=(${@}) failures=0

   while [ ${#all[@]} -ne 0 ] ; do
      local batch=("${all[@]:0:78}")

      all=("${all[@]:78}")

      if ! rng_add_tls "${batch[@]}" ; then
         echo >/dev/stderr "Batch of ${#batch[@]} failed."

         ((++failures))

         if [ ${failures} -ge 3 ] ; then
            echo >/dev/stderr "Too many batches failed."
            return 1
         fi
      fi
   done
}

rng_generate_binary()
{
   _rng_update || exit 1
   local ctr_iv=$(_rng_generate_key "ctr_iv" 16) || exit 1

   _rng_update || exit 1
   local ctr_key=$(_rng_generate_key "ctr_key" 32) || exit 1

   _rng_update || exit 1
   local cbc_iv=$(_rng_generate_key "cbc_iv" 16) || exit 1

   _rng_update || exit 1
   local cbc_key=$(_rng_generate_key "cbc_key" 32) || exit 1

   _rng_update || exit 1

   _rng_generate ${1} \
  | openssl enc -aes-256-ctr -K ${ctr_key} -iv ${ctr_iv} 2> /dev/null \
  | openssl enc -aes-256-cbc -nopad -K ${cbc_key} -iv ${cbc_iv} 2> /dev/null \
  || exit 1

  rng_stir || exit 1
}

rng_generate()
{
   rng_generate_binary ${1} | _rng_bin_to_hex || exit 1
}

_rng_fetch_url()
{
   timeout 12 curl -s ${1} && return 0

   echo >/dev/stderr "Unable to fetch ${1}"

   return 1
}

_rng_fetch_all()
{
   local nist_pid nist_ret random_pid random_ret anu_pid anu_ret hotbits_pid hotbits_ret

   _rng_fetch_url https://beacon.nist.gov/rest/record/last && echo -n >/dev/stderr N &

   nist_ret=$?
   nist_pid=$!

   _rng_fetch_url "https://www.random.org/integers/?num=20&min=-1000000000&max=1000000000&col=1&base=16&format=plain&rnd=new" && echo -n >/dev/stderr R &

   random_ret=$?
   random_pid=$!

   _rng_fetch_url "https://qrng.anu.edu.au/API/jsonI.php?length=8&type=hex16&size=16" && echo -n >/dev/stderr A &

   anu_ret=$?
   anu_pid=$!

   _rng_fetch_url "https://www.fourmilab.ch/cgi-bin/Hotbits?nbytes=64&fmt=bin&npass=1&lpass=8&pwtype=3" | base64 -e && echo -n >/dev/stderr H &

   hotbits_ret=$?
   hotbits_pid=$!

   local failures=0

   if [ ${nist_ret} -ne 0 ] || ! wait ${nist_pid} ; then
      echo >/dev/stderr "Unable to read nist" 

      ((++failures))

      if [ ${failures} -ge 2 ]; then      
         echo >/dev/stderr Giving up
         wait

         exit 1
      fi
   fi

   if [ ${random_ret} -ne 0 ] || ! wait ${random_pid} ; then
      echo >/dev/stderr "Unable to read random" 

      ((++failures))

      if [ ${failures} -ge 2 ]; then      
         echo >/dev/stderr Giving up
         wait

         exit 1
      fi
   fi

   if [ ${anu_ret} -ne 0 ] || ! wait ${anu_pid} ; then
      echo >/dev/stderr "Unable to read anu" 

      ((++failures))

      if [ ${failures} -ge 2 ]; then      
         echo >/dev/stderr Giving up
         wait

         exit 1
      fi
   fi

   if [ ${hotbits_ret} -ne 0 ] || ! wait ${hotbits_pid} ; then
      echo >/dev/stderr "Unable to read hotbits" 

      ((++failures))

      if [ ${failures} -ge 2 ]; then      
         echo >/dev/stderr Giving up
         wait

         exit 1
      fi
   fi

   echo >/dev/stderr
}

rng_stir_with_sites()
{
   local allSites localSites

   readarray -t allSites < <(sort -uR sites* | head -${1:-30}) || exit 1

   # If we have a sites.local, we make sure to use all of them.
   # Since they get included in allSites, it is possible that
   # some will be reused.
   if [ -e sites.local ] ; then
      readarray -t localSites < <(sort -uR sites.local) || exit 1
      if [ ${#localSites[@]} -ne 0 ] ; then
         if ! _rng_add_multi_tls "${localSites[@]}" ; then
            echo >/dev/stderr "Local site stir failed."
            rng_stir_with_external
            exit 1
         fi
      fi
   fi

   if ! _rng_add_multi_tls "${allSites[@]}" ; then
      echo >/dev/stderr "Site stir failed."
      rng_stir_with_external
      exit 1
   fi
}

rng_initialize()
{
   local start_time=`date`

   local public_entropy

   public_entropy=$(_rng_fetch_all) || exit 1

   local uname=`uname -a`

   rng_raw="${start_time}
${BASHPID}
${uname}
${public_entropy}"

   rng_raw=$(echo "${rng_raw}" | dd obs=16 fillchar=x conv=osync 2>/dev/null ) || exit 1

#echo >/dev/stderr rng_raw: "${rng_raw}"

# Note well:  All of this function's sources above this comment are
# public.  They are meant to make sure that each run is unique and
# uncorrelated with other runs on this or any other system.

   rng_pool=$(echo -n "${rng_raw}" | base64 -e) || exit 1

# The sysctl should also be considered public information.  However, it
# is unlikely that two runs will give the same results.

   rng_sysctl_add_and_stir || exit 1

# At this point, rng_pool should be universally unique.  Now we'll try to
# fetch something entropy-ish.  The whole premise is that for at least some
# runs, at least one TLS connection is not observed.
   rng_stir_with_external || exit 1

   rng_stir_with_sites 1500 || exit 1

   rng_stir_with_external || exit 1

#echo >/dev/stderr pool length: ${#rng_pool} count: ${rng_count}
}

rng_update_keys()
{
   rng_stir || exit 1

   _rng_rekey || exit 1
   iv=$(rng_generate 16) || exit 1
   _rng_rekey || exit 1
   key=$(rng_generate 32) || exit 1
   _rng_rekey || exit 1
   stir=$(rng_generate 64) || exit 1

   rng_stir || exit 1
}

_rng_generate_output()
{
   local repeat

   for ((repeat = 0; repeat < ${1} ; ++repeat)) ; do
      rng_generate_binary 16 || exit 1
   done
}

rng_reseed_pool()
{
   rng_sysctl_add_and_stir || exit 1

   rng_stir_with_sites 1200 || exit 1

   rng_sysctl_add_and_stir || exit 1

   rng_stir_with_external || exit 1
}


rng_initialize_pool()
{
   rng_initialize || exit 1

   rng_reseed_pool || exit 1
}

rng_generate_output()
{
   rng_stir || exit 1

   _rng_rekey || exit 1
   local output_iv=$(rng_generate 16) || exit 1
   _rng_rekey || exit 1
   local output_key=$(rng_generate 32) || exit 1

   _rng_rekey || exit 1
   local ctr_iv=$(rng_generate 16) || exit 1
   _rng_rekey || exit 1
   local ctr_key=$(rng_generate 32) || exit 1

   _rng_rekey || exit 1
   _rng_generate_output ${1} \
   | openssl enc -aes-256-ctr -nosalt -K ${ctr_key} -iv ${ctr_iv} 2> /dev/null \
   | openssl aes-256-cbc -e -K ${output_key} -iv ${output_iv} -nopad \
   || exit 1

   rng_stir || exit 1
}

fi

