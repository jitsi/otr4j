otr4j is an implementation of the [OTR (Off The Record) protocol][1]
in java.

Off-the-Record Messaging, is a cryptographic protocol that uses a
combination of the Advanced Encryption Standard (AES), the
Diffie-Hellman key exchange, and the SHA hash functions. In addition
to authentication and encryption, OTR provides perfect forward secrecy
and malleable encryption. The OTR protocol was designed by [Ian
Goldberg and the OTR Development Team][2].

otr4j development started during the Google Summer of Code 2009 where
the goal was to add support for OTR in SIP Communicator (now called
[jitsi][3]).

Recently, [devrandom][4] from [the Guardian project][6] ported SMP
support from java-otr to otr4j and [redsolution][5] moved the project
to github and did various fixes.

Other people might have added features to otr4j too so I move upstream
here to github in an effort to facilitate people contributing back to
the project.

  [1]: http://www.cypherpunks.ca/otr/
  [2]: http://www.cypherpunks.ca/otr/people.php
  [3]: http://www.jitsi.org/
  [4]: http://github.com/devrandom
  [5]: http://github.com/redsolution
  [6]: http://theguardianproject.info
