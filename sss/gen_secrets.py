import os
import sys

RAND_BYTES=192

sss_dir = sys.argv[1]
sed_dir = sys.argv[2]

ca_file = os.path.join(sss_dir, 'ca.crt')
crt_file = os.path.join(sed_dir, 'sed.crt')
key_file = os.path.join(sed_dir, 'sed.key')
sec_c_file = os.path.join(sed_dir, 'sed_secrets.c')
sec_h_file = os.path.join(sed_dir, 'sed_secrets.h')

cfp = open(sec_c_file, 'w')
hfp = open(sec_h_file, 'w')


# Write guards to header
hfp.write('#ifndef SED_SECRETS_H\n')
hfp.write('#define SED_SECRETS_H\n\n')


# Format CA
ifp = open(ca_file, 'r')
# Format lines as: "<chars>\r\n" \
s = ''.join('\"' + line.rstrip() + '\\r\\n\" \\' + '\n' for line in ifp.readlines())
# Remove final |  -- add ;
s = s[0:len(s)-3] + ';\n\n'
s = '\nconst char provision_ca[] = ' + s
ifp.close()

# Write CA
cfp.write(s)
hfp.write('extern const char provision_ca[];\n')


# Format cert
ifp = open(crt_file, 'r')
# Format lines as: "<chars>\r\n" \
s = ''.join('\"' + line.rstrip() + '\\r\\n\" \\' + '\n' for line in ifp.readlines())
# Remove final |  -- add ;
s = s[0:len(s)-3] + ';\n\n'
s = 'const char sed_provision_crt[] = ' + s
ifp.close()

# Write cert
cfp.write(s)
hfp.write('extern const char sed_provision_crt[];\n')


# Format key
ifp = open(key_file, 'r')
# Format lines as: "<chars>\r\n" \
s = ''.join('\"' + line.rstrip() + '\\r\\n\" \\' + '\n' for line in ifp.readlines())
# Remove final |  -- add ;
s = s[0:len(s)-3] + ';\n\n'
s = 'const char sed_provision_key[] = ' + s
ifp.close()

# Write key
cfp.write(s)
hfp.write('extern const char sed_provision_key[];\n')


# Generate and format rand bytes
rands = os.urandom(RAND_BYTES).hex()
array = list(map(''.join, zip(*[iter(rands)]*2)))
# Format as 0x?? chars
s = ''.join(map(lambda i: '0x' + i + ',', array))
s = '{' + s[0:len(s)-1] + '};\n\n'
s = 'const unsigned char initial_seed_pool[] = ' + s

# Write rand bytes
cfp.write(s)
hfp.write('extern const unsigned char initial_seed_pool[];\n')


# Write closing guard to header
hfp.write('\n#endif // SED_SECRETS_H\n')

# Close files
cfp.close()
hfp.close()