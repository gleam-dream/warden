%% Small trusted helpers for Warden: entropy, digests, constant-time
%% comparison, PEM trust anchors and JSON-term checks. No function here logs,
%% formats or returns secret material beyond its explicit result.
-module(warden_ffi).

-export([
    random_token/1,
    s256/1,
    sha256_hex/1,
    constant_time_equal/2,
    pem_certificates/1,
    now_seconds/0,
    now_millis/0,
    is_json_term/1,
    jwk_signing_key/1,
    unique_integer/0,
    identity/1
]).

%% `Bytes` bytes from the OS CSPRNG, base64url without padding.
random_token(Bytes) when is_integer(Bytes), Bytes >= 16 ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).

%% RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))).
s256(Verifier) when is_binary(Verifier) ->
    base64:encode(crypto:hash(sha256, Verifier), #{mode => urlsafe, padding => false}).

sha256_hex(Value) when is_binary(Value) ->
    binary:encode_hex(crypto:hash(sha256, Value), lowercase).

%% Compares digests of both inputs so that the comparison time does not
%% depend on where the inputs first differ, including when lengths differ.
constant_time_equal(A, B) when is_binary(A), is_binary(B) ->
    crypto:hash_equals(crypto:hash(sha256, A), crypto:hash(sha256, B)) andalso
        byte_size(A) =:= byte_size(B).

%% DER certificates from PEM text; `{error, nil}` when none are present or the
%% text is malformed.
pem_certificates(Pem) when is_binary(Pem) ->
    try public_key:pem_decode(Pem) of
        Entries ->
            case [Der || {'Certificate', Der, not_encrypted} <- Entries] of
                [] -> {error, nil};
                Ders -> {ok, Ders}
            end
    catch
        _:_ -> {error, nil}
    end.

now_seconds() -> erlang:system_time(second).
now_millis() -> erlang:system_time(millisecond).
unique_integer() -> erlang:unique_integer([positive, monotonic]).
identity(X) -> X.

%% True when `Term` is a JSON value as produced by `json:decode/1`: binaries,
%% numbers, booleans, null, lists and maps with binary keys. Warden stores
%% only such terms as claims, so decoders never meet arbitrary foreign terms.
is_json_term(Term) when is_binary(Term); is_number(Term) -> true;
is_json_term(true) -> true;
is_json_term(false) -> true;
is_json_term(null) -> true;
is_json_term(List) when is_list(List) -> lists:all(fun is_json_term/1, List);
is_json_term(Map) when is_map(Map) ->
    maps:fold(fun(K, V, Acc) -> Acc andalso is_binary(K) andalso is_json_term(V) end, true, Map);
is_json_term(_) -> false.

%% Parse a private JWK (JSON text) for private_key_jwt. Returns the algorithm
%% the key supports and its key id, never the key material.
jwk_signing_key(Json) when is_binary(Json) ->
    try
        Map = json:decode(Json),
        true = is_map(Map),
        Jwk = jose_jwk:from_map(Map),
        {_, Fields} = jose_jwk:to_map(Jwk),
        Private =
            case maps:get(<<"kty">>, Fields, undefined) of
                <<"RSA">> -> maps:is_key(<<"d">>, Fields);
                <<"EC">> -> maps:is_key(<<"d">>, Fields);
                <<"OKP">> -> maps:is_key(<<"d">>, Fields);
                _ -> false
            end,
        case Private of
            true ->
                Kid =
                    case maps:get(<<"kid">>, Map, undefined) of
                        K when is_binary(K) -> {some, K};
                        _ -> none
                    end,
                Algs = signing_algs(Jwk),
                {ok, {Kid, Algs}};
            false ->
                {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.

signing_algs(Jwk) ->
    case jose_jwk:to_map(Jwk) of
        {_, #{<<"kty">> := <<"RSA">>}} -> [<<"RS256">>, <<"PS256">>];
        {_, #{<<"kty">> := <<"EC">>, <<"crv">> := <<"P-256">>}} -> [<<"ES256">>];
        {_, #{<<"kty">> := <<"EC">>, <<"crv">> := <<"P-384">>}} -> [<<"ES384">>];
        {_, #{<<"kty">> := <<"EC">>, <<"crv">> := <<"P-521">>}} -> [<<"ES512">>];
        {_, #{<<"kty">> := <<"OKP">>, <<"crv">> := <<"Ed25519">>}} -> [<<"EdDSA">>];
        _ -> []
    end.
