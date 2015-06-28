initSidebarItems({"struct":[["Data","Top-level type: a representation of \"Structured Data\"."],["FixedAttributes","Attributes of the `Data` which can never change once initially set.  These define the identity, type and some of the rules the network will employ for handling the `Data`.  It can also hold arbitrary data which will likely be meaningless to the network."],["KeyAndWeight","A representation of an owner's public key and the bias which should be given to that key when a mutating request is received by the network."],["MutableAttributes","Attributes of the `Data` which can be changed via a properly-authorised request to the network. These define the current owner's public keys, further rules the network will employ for handling the `Data` and also arbitrary data which will likely be meaningless to the network."],["Version","A representation of a single version.  The `index` allows provision of strict total ordering of the `Version`s.  It can also hold arbitrary data specific to that particular `Version`, e.g. encrypted content or the name of a piece of \"Immutable Data\"."]]});