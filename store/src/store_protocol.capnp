@0xf4bd406fa822c9db;

interface Node {
  new @0 (home: Text, domain: Text, ephemeral: Bool, name: Text) -> (result: Result(Store));

  interface Store {
    add @0 (label: Text, fingerprint: Text) -> (result: Result(Binding));
    lookup @1 (label: Text) -> (result: Result(Binding));
    delete @2 ();
    #iterate @3 (id: UInt32) -> (result: Result(Binding));
  }

  interface Binding {
    stats @0 () -> (result: Result(Stats));
    key @1 () -> (result: Result(Key));
    import @2 (key: Data, force: Bool) -> (result: Result(Data));
    delete @3 ();
    registerEncryption @4 () ->   (result: Result(Stats));
    registerVerification @5 () -> (result: Result(Stats));
  }

  interface Key {
    stats @0 () -> (result: Result(Stats));
    tpk @1() -> (result: Result(Data));
    import @2 (key: Data) -> (result: Result(Data));
  }

  struct Stats {
    created @0 :Int64;
    updated @1 :Int64;
    encryptionCount @2 :Int64;
    encryptionFirst @3 :Int64;
    encryptionLast  @4 :Int64;
    verificationCount @5 :Int64;
    verificationFirst @6 :Int64;
    verificationLast  @7 :Int64;
  }

  enum Error {
    unspecified @0;
    notFound @1;
    conflict @2;
    systemError @3;
    malformedKey @4;
  }

  struct Result(T) {
    union {
      ok @0 :T;
      err @1 :Error;
    }
  }
}
