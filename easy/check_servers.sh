#!/usr/local/bin/bash

print_cipher()
{
   local cipher=$(awk '/Cipher +:/ { print $3 } /Master-Key:/ { print $2 | "xxd -r -p >> keys.bin"  }')

   if [ ${#cipher} -eq 0 ] ; then
      printf "failed %s\n" ${1}
      return 1
   fi

   printf "%s %s\n" ${cipher} ${1}
}

tls()
{
   timeout 10 openssl s_client -connect ${1}:443 -no_ssl2 -no_ssl3 -CAfile /usr/local/etc/ssl/cert.pem < /dev/null 2>/dev/null \
         | print_cipher ${1} \
      && return 0
   
   if [ ${1} = www.* ] ; then
      exit 1
   fi

   local withwww=www.${1}

   timeout 10 openssl s_client -connect ${withwww}:443 -no_ssl2 -no_ssl3 -CAfile /usr/local/etc/ssl/cert.pem < /dev/null 2>/dev/null \
         | print_cipher ${withwww} \
      && return 0

   exit 1
}

while read l; do
   tls ${l} &

   while (( $( jobs -p | wc -w ) > 100 )); do
      wait -n;
   done
done < <(sort --unique | sort --random-sort )

wait

