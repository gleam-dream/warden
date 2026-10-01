%% Disposable test PKI. Generation lives in `scripts/test-pki` (OpenSSL);
%% this module locates the files and decodes the CA for Erlang tests.
-module(warden_test_pki).

-export([generate/1, ca_der/1]).

generate(Dir) ->
    Script = filename:join(filename:dirname(filename:dirname(filename:absname(Dir))), "scripts/test-pki"),
    _ = os:cmd(Script),
    list_to_binary(Dir).

ca_der(Dir) ->
    {ok, Pem} = file:read_file(filename:join(unicode:characters_to_list(Dir), "ca.pem")),
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    Der.
