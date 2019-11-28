@0xf4bd406fa822c9db;

interface Node {
  open @0 (realm: Text, networkPolicy: NetworkPolicy, ephemeral: Bool, name: Text)
         -> (result: Result(Mapping));
  iter @1 (realmPrefix: Text) -> (result: Result(MappingIter));
  iterKeys @2 () -> (result: Result(KeyIter));
  log @3 () -> (result: Result(LogIter));
  import @4 (key: Data) -> (result: Result(Key));
  lookupByKeyid @5 (keyid: UInt64) -> (result: Result(Key));
  lookupByFingerprint @6 (fingerprint: Text) -> (result: Result(Key));
  lookupBySubkeyid @7 (keyid: UInt64) -> (result: Result(Key));

  interface Mapping {
    add @0 (label: Text, fingerprint: Text) -> (result: Result(Binding));
    lookup @1 (label: Text) -> (result: Result(Binding));
    delete @2 () -> (result: Result(Unit));
    iter @3 () -> (result: Result(BindingIter));
    log @4 () -> (result: Result(LogIter));
    lookupBySubkeyid @5 (keyid: UInt64) -> (result: Result(Binding));
  }

  interface Binding {
    stats @0 () -> (result: Result(Stats));
    key @1 () -> (result: Result(Key));
    import @2 (key: Data, force: Bool) -> (result: Result(Data));
    delete @3 () -> (result: Result(Unit));
    registerEncryption @4 () ->   (result: Result(Stats));
    registerVerification @5 () -> (result: Result(Stats));
    log @6 () -> (result: Result(LogIter));
    label @7 () -> (result: Result(Text));
  }

  interface Key {
    stats @0 () -> (result: Result(Stats));
    cert @1() -> (result: Result(Data));
    import @2 (key: Data) -> (result: Result(Data));
    log @3 () -> (result: Result(LogIter));
  }

  # Iterators.
  interface MappingIter {
    next @0 () -> (result: Result(Item));

    struct Item {
      realm @0 :Text;
      name @1 :Text;
      networkPolicy @2 :NetworkPolicy;
      mapping @3 :Mapping;
    }
  }

  interface BindingIter {
    next @0 () -> (result: Result(Item));

    struct Item {
      label @0 :Text;
      fingerprint @1 :Text;
      binding @2 :Binding;
    }
  }

  interface KeyIter {
    next @0 () -> (result: Result(Item));

    struct Item {
      fingerprint @0 :Text;
      key @1 :Key;
    }
  }

  interface LogIter {
    next @0 () -> (result: Result(Entry));

    struct Entry {
      timestamp @0 :Int64;
      mapping   @1 :Mapping;
      binding   @2 :Binding;
      key       @3 :Key;
      slug      @4 :Text;
      message   @5 :Text;
      error     @6 :Text;
    }
  }

  # Unit struct.  Useful with Result.
  struct Unit {}

  struct Stats {
    created @0 :Int64;
    updated @1 :Int64;
    encryptionCount   @2 :Int64;
    encryptionFirst   @3 :Int64;
    encryptionLast    @4 :Int64;
    verificationCount @5 :Int64;
    verificationFirst @6 :Int64;
    verificationLast  @7 :Int64;
  }

  struct Log {
    timestamp @0 :Int64;
    item @1 :Text;
    message @2 :Text;
    error @3 :Text;
  }

  enum NetworkPolicy {
    offline @0;
    anonymized @1;
    encrypted @2;
    insecure @3;
  }

  enum Error {
    unspecified @0;
    notFound @1;
    conflict @2;
    systemError @3;
    malformedCert @4;
    networkPolicyViolationOffline @5;
    networkPolicyViolationAnonymized @6;
    networkPolicyViolationEncrypted @7;
    networkPolicyViolationInsecure @8;
    malformedFingerprint @9;
  }

  struct Result(T) {
    union {
      ok @0 :T;
      err @1 :Error;
    }
  }
}
