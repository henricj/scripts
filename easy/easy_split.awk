BEGIN {
   FS="$";
   ValidDomain="^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]+$";
}

/domain=/ {
   #print "domain match full line:", $0 
   #print "domain match:", $2 
   
   domainstart=index($2, "domain=")

   if(domainstart > 0) {
      n=split(substr($2, domainstart+7), domains, "|");

      for(i=1; i<=n; ++i) {
         url=domains[i];
         if (substr(url, 1, 1) == "~")
            url=substr(url, 2);

         if (url ~ ValidDomain)
            print url;
      }
   }
}

/^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]+,?)+#[#@]#/ {
   hashindex=index($0, "#");

   if (hashindex > 1) {
      n = split(substr($0, 1, hashindex-1), domains, ",");

      for(i=1; i<=n; ++i) {
         url=domains[i];

         if (substr(url, 1, 1) == "~")
            url=substr(url, 2);

         if (url ~ ValidDomain)
            print url;
      }
   }
}

/^(@@)?\|\|/ {
   endanchor=index($1, "^");

   if (endanchor >= 4) {
      offset=3;
      if ("@" == substr($1, 1, 1))
         offste=5;

      url=substr($1, offset, endanchor - 3);

      star=index(url, "*");
      if(star > 0)
         url=substr(url, 1, star - 1);

      slash=index(url, "/");
      if(slash > 0)
         url=substr(url, 1, slash - 1);
   
      if (url ~ ValidDomain)
         print url;
   }
}

{
   if ($0 ~ ValidDomain)
      print $0;
}

