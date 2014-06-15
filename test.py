import filecmp

plaintext_files=['./tony/tony.txt','./alice/alice.txt']
decrypted_files=['./alice/tony_decr.txt','./tony/alice_decr.txt']

print 'Auto Test Script, Running...............'
for i in range(0,len(plaintext_files)):
  if not filecmp.cmp(plaintext_files[i],decrypted_files[i]):
    print 'Decrypted File Not match: ' + plaintext_files[i] + "  " + decrypted_files[i]
print "Decrypted Files All match"
