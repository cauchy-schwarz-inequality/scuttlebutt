-module(scuttlebutt).

%% API exports
-export([test/0]).

%%====================================================================
%% API functions
%%====================================================================

%% Bootstrapping unit tests here until
%% Simulate a successful handshake between two peers and die loudly if any step fails
%% TODO: Port these to use eunit
test() ->
    write_keys_to_file(),
    read_keyfile(),
    #{public := ClientLongTermPublicKey, secret := ClientLongTermSecret } = enacl:crypto_sign_ed25519_keypair(),
    #{public := ServerLongTermPublicKey, secret := ServerLongTermSecret } = enacl:crypto_sign_ed25519_keypair(),
    #{public := ClientEphemeralPublicKey, secret := ClientEphemeralSecret } = generate_curve25519_keypair(),
    #{public := ServerEphemeralPublicKey, secret := ServerEphemeralSecret } = generate_curve25519_keypair(),
    %% Magic identifier used in the Scuttleverse hardcoded into many applications
    %% TODO: parametrize this value
    NetworkIdentifier = base64:decode("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s="),
    ClientHello = client_hello_message(NetworkIdentifier, ClientEphemeralPublicKey),
    verify_hello(ClientHello, NetworkIdentifier),
    ClientSharedSecret = derive_shared_secret(ClientEphemeralSecret, ServerEphemeralPublicKey),
    ServerSharedSecret = derive_shared_secret(ServerEphemeralSecret, ClientEphemeralPublicKey),
    ClientSharedSecret = ServerSharedSecret,
    ClientSecondSharedSecret = client_generate_second_shared_secret(ClientEphemeralSecret, ServerLongTermPublicKey),
    ServerSecondSharedSecret = server_generate_second_shared_secret(ServerLongTermSecret, ClientEphemeralPublicKey),
    ClientSecondSharedSecret = ServerSecondSharedSecret,
    ClientDetachedSignature = detached_signature(NetworkIdentifier, ServerLongTermPublicKey, ClientSharedSecret, ClientLongTermSecret),
    ClientSecretBox = client_secret_box(ClientDetachedSignature, ClientLongTermPublicKey, NetworkIdentifier, ClientSharedSecret, ClientSecondSharedSecret),
    server_open_box(ClientSecretBox, NetworkIdentifier, ClientSharedSecret, ClientSecondSharedSecret, ServerLongTermPublicKey).


%%====================================================================
%% Internal functions
%%====================================================================


write_keys_to_file() ->
    #{public := PublicKey, private := PrivateKey} = enacl:crypto_sign_ed25519_keypair(),
    Algorithm = ".ed25519",
    Base64Public = base64:encode_to_string(PublicKey) ++ Algorithm,
    Base64Private = "@" ++ base64:encode_to_string(PrivateKey) ++ Algorithm,
    Keys = [
	    {<<"curve">>, <<"ed25519">>},
	    {<<"public">>, list_to_binary(Base64Public)},
	    {<<"private">>, list_to_binary(Base64Private)},
	    {<<"id">>, list_to_binary(Base64Public)}
    ],
    KeyJson = jsx:prettify(jsx:encode(Keys)),
    file:delete("secret"),
    {ok, S} = file:open("secret", [append, binary]),
    %% Copying the copy in https://github.com/ssbc/ssb-keys/blob/master/storage.js#L32 
    %% TODO: Do this in fewer filesystem operations :)
    io:format(S, <<"/*~n">>, []),
    io:format(S, <<"  this is your SECRET name.~n">>, []),
    io:format(S, <<"  this name gives you magical powers.~n">>, []),
    io:format(S, <<"  with it you can mark your messages so that your friends can verify~n">>, []),
    io:format(S, <<"  that they really did come from you.~n">>, []),
    io:format(S, <<"*/~n">>, []),
    io:format(S, <<"~n">>, []),
    io:format(S, "~s~n", [KeyJson]),
    io:format(S, <<"~n">>, []),
    io:format(S, <<"/*~n">>, []),
    io:format(S, <<"  WARNING! It's vital that you DO NOT edit OR share your secret name~n">>, []),
    io:format(S, <<"  instead, share your public name~n">>, []),
    io:format(S, "  your public name: @~s~n", [Base64Public]),
    io:format(S, <<"*/">>, []),
    file:close(S).

read_keyfile() ->
    {ok, Data} = file:read_file("secret"),
    jsx:decode(Data).

%% Generates an X25519 keypair 
generate_curve25519_keypair() ->
    #{public := Ed25519Public, secret := Ed25519Private} = enacl:crypto_sign_ed25519_keypair(),
    #{public => enacl:crypto_sign_ed25519_public_to_curve25519(Ed25519Public),
      secret => enacl:crypto_sign_ed25519_secret_to_curve25519(Ed25519Private)}.

%% Generates an HMAC and appends the client's ephemeral public key using the NetworkIdentifier
%% as the shared secret
client_hello_message(NetworkIdentifier, PublicKey) ->
    HMAC = enacl:auth(NetworkIdentifier, PublicKey),
    <<HMAC/binary, PublicKey/binary>>.

%% The server compares the 64 bit HMAC/EphemeralPubKey binary with the 
%% NetworkIdentifier as the shared secret
verify_hello(<<HMAC:32/binary, ClientEphemeralPubKey:32/binary>>, NetworkIdentifier) ->
    enacl:auth_verify(HMAC, NetworkIdentifier, ClientEphemeralPubKey).

derive_shared_secret(ClientEphemeralSecretKey, ServerEphemeralPublicKey) ->
    enacl:curve25519_scalarmult(ClientEphemeralSecretKey, ServerEphemeralPublicKey).

client_generate_second_shared_secret(ClientEphemeralSecret, ServerLongTermPublicKey) ->
    enacl:curve25519_scalarmult(ClientEphemeralSecret, enacl:crypto_sign_ed25519_public_to_curve25519(ServerLongTermPublicKey)).

server_generate_second_shared_secret(ServerLongTermSecret, ClientEphemeralPublicKey) ->
    enacl:curve25519_scalarmult(enacl:crypto_sign_ed25519_secret_to_curve25519(ServerLongTermSecret), ClientEphemeralPublicKey).

detached_signature(NetworkIdentifier, ServerLongTermPublicKey, SharedSecret, ClientLongTermSecret) ->
    HashedSecret = crypto:hash(sha256, SharedSecret),
    Message = <<NetworkIdentifier/bytes, ServerLongTermPublicKey/bytes, HashedSecret/bytes>>,
    enacl:sign_detached(Message, ClientLongTermSecret).

make_box_key(NetworkIdentifier, SharedSecret, SecondSharedSecret) ->
    crypto:hash(sha256, <<NetworkIdentifier/binary, SharedSecret/binary, SecondSharedSecret/binary>>).

client_secret_box(DetachedSignature, ClientLongTermPublicKey, NetworkIdentifier, SharedSecret, SecondSharedSecret) ->
    Message = <<DetachedSignature/binary, ClientLongTermPublicKey/binary>>,
    %% Nonce is 24 bytes of 0s -- this is OK because this is the only secret box that will ever use 
    %% the BoxKey as defined below.
    Nonce = <<0:(24*8)>>,
    BoxKey = make_box_key(NetworkIdentifier, SharedSecret, SecondSharedSecret),
    enacl:box_afternm(Message, Nonce, BoxKey).

server_open_box(Box, NetworkIdentifier, SharedSecret, SecondSharedSecret, ServerLongTermPublicKey) ->
    Nonce = <<0:(24*8)>>,
    BoxKey = make_box_key(NetworkIdentifier, SharedSecret, SecondSharedSecret),
    {ok, BoxPlainText} = enacl:box_open_afternm(Box, Nonce, BoxKey),
    96 = byte_size(BoxPlainText),
    <<DetachedSignature:64/binary, ClientLongTermPublicKey:32/binary>> = BoxPlainText,
    Message = <<NetworkIdentifier/binary, ServerLongTermPublicKey/binary, (crypto:hash(sha256, SharedSecret))/binary>>,
    enacl:sign_verify_detached(DetachedSignature, Message, ClientLongTermPublicKey).
    
client_derive_shared_secret(ClientLongTermSecret, ServerEphemeralPublicKey) ->
    enacl:scalar_mult(enacl:crypto_sign_ed25519_secret_to_curve25519(ClientLongTermSecret), ServerEphemeralPublicKey).

server_derive_shared_secret(ServerEphemeralSecret, ClientLongTermPublicKey) ->
    enacl:scalar_mult(ServerEphemeralSecret, enacl:crypto_sign_ed25519_public_to_curve25519(ClientLongTermPublicKey)).
