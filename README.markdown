## Synopsis

otr4j is an implementation of the [OTR (Off The Record) protocol][1]
in java. Its development started during the GSoC '09
where the goal was to add support for OTR in [jitsi][2]. It currently
supports OTRv1, [OTRv2][] and [OTRv3][]. Additionally, there is support
for fragmenting outgoing messages.

For a quick introduction on how to use the library have a look at the
[DummyClient](src/test/java/net/java/otr4j/session/DummyClient.java).

## Maven

If you use maven for managing your project lifecycle and you want to
use otr4j in your project, just add the following dependency to your
the pom.xml:

**IMPORTANT** otr4j has moved to Maven Central! I will be making releases to the
old repository for the foreseeable future, but it is highly recommended to
update your settings!

```xml
<dependency>
    <groupId>org.jitsi</groupId>
    <artifactId>org.otr4j</artifactId>
    <version>0.23</version>
</dependency>
```

## Contributing

Want to hack on otr4j? Awesome! Here are the guidelines we'd like you to follow:

* _All_ contributors submit code via pull requests. NOTE that before we can accept any patches from you, we need you to sign our contributor agreement available [here](https://github.com/jitsi/jitsi/blob/master/CONTRIBUTING.md#contributor-license-agreement).
* New commits must be pushed by the reviewer of the pull request, not the author.
* Any developer can request push access and become a committer, regardless of project or organization affiliation.
* We choose committers primarily on the Hippocratic Principle. You can find out more about the exact procedure [here][bca].

  [1]: https://otr.cypherpunks.ca/
  [2]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
  [bca]: https://jitsi.org/Documentation/CommitAccess

