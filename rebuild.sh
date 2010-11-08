make realclean
rm CIF-Client*.tar.gz -f
rm MANIFEST
perl Makefile.PL
make manifest
make
make dist
