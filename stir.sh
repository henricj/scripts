#!/usr/local/bin/bash

set -o pipefail

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

      tls ${site} &
      
      ret=$?
      pid=$! 

      if [ ${ret} -ne 0 ] ; then
         echo "Unable to read" ${site}
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
   | openssl dgst -sha512 -binary \
   | openssl rand -rand /dev/stdin:/dev/random -hex ${1} 2> /dev/null
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
      { echo ${rng_pool} | base64 -d ; } \
      | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
      | base64 -e) || exit 1

   # Prevent accidental reuse
   unset rng_key rng_iv || exit 1
  
   _rng_update || exit 1
 
   _rng_generate_block "stir" \
      | openssl rand -rand /dev/stdin:/dev/random -hex 32 2>/dev/null >/dev/null
}

# Add entropy from given URL
rng_add_tls()
{
   local pool code

   for retry in {1..3} ; do
      _rng_rekey || exit 1

      # The TLS connection's master key is the important part
      pool=$( \
         { multi_tls "${@}" && echo ${rng_pool} | base64 -d ; } \
         | openssl aes-256-cbc -e -K ${rng_key} -iv ${rng_iv} \
         | base64 -e )

      code=$?

      # Prevent accidental reuse
      unset rng_key rng_iv || exit 1
      
      rng_stir || exit 1
      
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
   _rng_generate ${1} || exit 1

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

   rng_raw="${nist_raw}
${random_raw}
${anu_raw}"

   rng_pool=$(echo "${rng_raw}" | base64 -e) || exit 1

   rng_stir || exit 1

   local allSites

   readarray -t allSites < <(sort -uR sites | head -25) || exit 1

   local split=$(( 2 * ${#allSites[*]} / 3 ))

   sites=("${allSites[@]:${split}}")

   local firstSites=("${allSites[@]:0:${split}}")

   rng_add_multi_tls "${firstSites[@]}"

   rng_stir || exit 1

#echo >/dev/stderr pool length: ${#rng_pool}
}

rng_tls()
{
   rng_keys || exit 1

   rng_update || exit 1

   keyed_rng_tls ${1} ${2} ${rng_key} ${rng_iv}
}

keyed_rng_tls()
{
   rng_update || exit 1

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
   iv=$(rng_generate 16) || exit 1

   key=$(rng_generate 32) || exit 1

   stir=$(rng_generate 64) || exit 1
}

rng_initialize || exit 1

if ! get_keys ; then
   echo >/dev/stderr get_keys failed
   exit 1
fi

#echo >/dev/stderr iv is $iv
#echo >/dev/stderr key is $key
#echo >/dev/stderr stir is $stir

rng_stir || exit 1

rng_add_multi_tls "${sites[@]}"

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
| openssl aes-256-cbc -e -K ${key} -iv ${iv} \
|| exit 1

rng_stir

