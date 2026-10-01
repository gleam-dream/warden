%% Disposable test PKI. Keys and certificates are generated per run and are
%% never used outside local tests. Nothing here disables verification: tests
%% trust the generated CA explicitly.
-module(warden_test_pki).

-include_lib("public_key/include/public_key.hrl").

-export([generate/1, ca_der/1]).

%% Writes ca.pem, localhost.{pem,key}, wrong_host.{pem,key},
%% self_signed.{pem,key}, expired.{pem,key} into Dir. Returns Dir.
generate(Dir0) ->
    Dir = unicode:characters_to_list(Dir0),
    ok = filelib:ensure_path(Dir),
    Now = calendar:universal_time(),
    {{Y, M, D}, _} = Now,
    Valid = {{Y - 1, M, 1}, {Y + 5, M, 1}},
    Expired = {{Y - 3, M, 1}, {Y - 2, M, 1}},
    _ = D,
    Root = public_key:pkix_test_root_cert("Warden Test CA", [
        {key, {rsa, 2048, 65537}}, {validity, Valid}, {digest, sha256}
    ]),
    leaf(Dir, "localhost", Root, [{dNSName, "localhost"}, {iPAddress, <<127, 0, 0, 1>>}], Valid),
    leaf(Dir, "wrong_host", Root, [{dNSName, "wrong.example"}], Valid),
    leaf(Dir, "expired", Root, [{dNSName, "localhost"}], Expired),
    Other = public_key:pkix_test_root_cert("Untrusted CA", [{key, {rsa, 2048, 65537}}, {digest, sha256}]),
    leaf(Dir, "self_signed", Other, [{dNSName, "localhost"}], Valid),
    #{cert := CaDer} = Root,
    ok = file:write_file(
        filename:join(Dir, "ca.pem"),
        public_key:pem_encode([{'Certificate', CaDer, not_encrypted}])
    ),
    list_to_binary(Dir).

ca_der(Dir) ->
    {ok, Pem} = file:read_file(filename:join(unicode:characters_to_list(Dir), "ca.pem")),
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    Der.

leaf(Dir, Name, Root, AltNames, Validity) ->
    Ext = #'Extension'{
        extnID = ?'id-ce-subjectAltName',
        critical = false,
        extnValue = AltNames
    },
    #{server_config := Server} = public_key:pkix_test_data(#{
        server_chain => #{
            root => Root,
            intermediates => [],
            peer => [{key, {rsa, 2048, 65537}}, {extensions, [Ext]}, {validity, Validity}, {digest, sha256}]
        },
        client_chain => #{
            root => [{key, {rsa, 2048, 65537}}],
            intermediates => [],
            peer => [{key, {rsa, 2048, 65537}}]
        }
    }),
    Cert = proplists:get_value(cert, Server),
    {KeyType, KeyDer} =
        case proplists:get_value(key, Server) of
            {T, K} when is_binary(K) -> {T, K};
            #{} = _ -> error(unexpected_key_format)
        end,
    ok = file:write_file(
        filename:join(Dir, Name ++ ".pem"),
        public_key:pem_encode([{'Certificate', Cert, not_encrypted}])
    ),
    ok = file:write_file(
        filename:join(Dir, Name ++ ".key"),
        public_key:pem_encode([{KeyType, KeyDer, not_encrypted}])
    ).
