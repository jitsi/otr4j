## Synopsis

otr4j is an implementation of the [OTR (Off The Record) protocol][1]
in java. Its development started during the Google Summer of Code 2009
where the goal was to add support for OTR in [jitsi][2]. It currently
supports OTRv1, [OTRv2][] and [OTRv3][]. Additionally, there is support
for fragmenting outgoing messages.

For a quick introduction on how to use the library have a look at the
[DummyClient](src/test/java/net/java/otr4j/session/DummyClient.java).

## Maven

If you use maven for managing your project lifecycle and you want to
use otr4j in your project, just add the following repository entry to
the pom.xml:

**IMPORTANT** Repository URL has changed !

```xml
<repository>
  <id>otr4j-repo</id>
  <name>otr4j repository on GitHub</name>
  <url>http://jitsi.github.com/otr4j/repository/</url>
</repository>
```

  [1]: https://otr.cypherpunks.ca/
  [2]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
