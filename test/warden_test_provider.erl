%% Scripted in-process OpenID provider for fast, deterministic tests.
%%
%% It serves discovery, JWKS, token and userinfo endpoints over TLS from the
%% disposable test PKI. Tests act as the browser: they read state and nonce
%% from Warden's authorization URL, register an authorization code with
%% `issue_code/3`, and build the callback themselves. Behaviour per code or
%% per endpoint is scripted through `script/3`.
%%
%% Signing uses erlang-jose (the library oidcc uses). Independent JOSE
%% evidence comes from the node-oidc-provider suite with panva/jose.
-module(warden_test_provider).

-export([
    start/0, start/1, stop/1, issuer/1, issue_code/3, script/3, token_requests/1,
    metadata/2, refresh_tokens/1, set_claims/2, sign/2, key/1, rotate_key/1
]).

-define(CLIENT, <<"warden-rp">>).

start() -> start(#{}).

start(Overrides) ->
    {ok, _} = application:ensure_all_started([ssl, jose]),
    Table = ets:new(warden_test_provider, [public, set]),
    Key = jose_jwk:generate_key({rsa, 2048}),
    Kid = <<"test-key-1">>,
    ets:insert(Table, [{key, Key, Kid}, {token_requests, 0}, {metadata_overrides, Overrides}, {claims, #{}}]),
    Handler = fun(Request) -> handle(Table, Request) end,
    Server = warden_test_server:start("localhost", Handler),
    ets:insert(Table, {issuer, warden_test_server:url(Server, "")}),
    #{server => Server, table => Table}.

stop(#{server := Server, table := Table}) ->
    warden_test_server:stop(Server),
    ets:delete(Table),
    nil.

issuer(#{table := Table}) -> lookup(Table, issuer).

key(#{table := Table}) ->
    [{key, Key, Kid}] = ets:lookup(Table, key),
    {Key, Kid}.

token_requests(#{table := Table}) -> lookup(Table, token_requests).

metadata(#{table := Table}, Overrides) ->
    ets:insert(Table, {metadata_overrides, Overrides}),
    nil.

%% Extra or replacement ID-token claims for every issued ID token.
set_claims(#{table := Table}, Claims) ->
    ets:insert(Table, {claims, Claims}),
    nil.

%% Register an authorization code bound to the transaction's nonce.
issue_code(#{table := Table}, Code, Nonce) ->
    ets:insert(Table, {{code, Code}, Nonce}),
    nil.

%% Script a behaviour for a token request: key is `{code, Code}`,
%% `{refresh, Token}` or `userinfo`. Behaviours:
%%   {delay, Ms}            respond normally after Ms
%%   {status, Status, Json} error response
%%   {id_token, Mutation}   see mutate/3
%%   omit_id_token | drop_refresh_token | close | malformed_json
script(#{table := Table}, Key, Behaviour) ->
    ets:insert(Table, {{script, Key}, Behaviour}),
    nil.

refresh_tokens(#{table := Table}) ->
    [T || {{refresh, T}, _} <- ets:tab2list(Table)].

%% Replace the signing key (new kid); the JWKS endpoint serves only the new key.
rotate_key(#{table := Table}) ->
    ets:insert(Table, {junk_keys, true}),
    Key = jose_jwk:generate_key({rsa, 2048}),
    Kid = base64:encode(crypto:strong_rand_bytes(6), #{mode => urlsafe, padding => false}),
    ets:insert(Table, {key, Key, Kid}),
    nil.

lookup(Table, Key) ->
    [{Key, V}] = ets:lookup(Table, Key),
    V.

%% ---------------------------------------------------------------------------

handle(Table, #{path := <<"/.well-known/openid-configuration">>}) ->
    Issuer = lookup(Table, issuer),
    Base = #{
        <<"issuer">> => Issuer,
        <<"authorization_endpoint">> => <<Issuer/binary, "/authorize">>,
        <<"token_endpoint">> => <<Issuer/binary, "/token">>,
        <<"userinfo_endpoint">> => <<Issuer/binary, "/userinfo">>,
        <<"introspection_endpoint">> => <<Issuer/binary, "/introspect">>,
        <<"end_session_endpoint">> => <<Issuer/binary, "/logout">>,
        <<"jwks_uri">> => <<Issuer/binary, "/jwks">>,
        <<"response_types_supported">> => [<<"code">>],
        <<"response_modes_supported">> => [<<"query">>, <<"form_post">>],
        <<"grant_types_supported">> => [<<"authorization_code">>, <<"refresh_token">>, <<"client_credentials">>],
        <<"subject_types_supported">> => [<<"public">>],
        <<"scopes_supported">> => [<<"openid">>, <<"email">>, <<"profile">>],
        <<"id_token_signing_alg_values_supported">> => [<<"RS256">>],
        <<"code_challenge_methods_supported">> => [<<"S256">>],
        <<"token_endpoint_auth_methods_supported">> => [<<"client_secret_basic">>, <<"client_secret_post">>, <<"none">>],
        <<"authorization_response_iss_parameter_supported">> => true
    },
    Merged = maps:merge(Base, lookup(Table, metadata_overrides)),
    json(200, maps:filter(fun(_, V) -> V =/= delete end, Merged));
handle(Table, #{path := <<"/jwks">>}) ->
    [{key, Key, Kid}] = ets:lookup(Table, key),
    {_, Public} = jose_jwk:to_public_map(Key),
    Real = Public#{<<"kid">> => Kid, <<"use">> => <<"sig">>, <<"alg">> => <<"RS256">>},
    %% Optional unusable keys listed before the real one (RFC 7517 §5 says a
    %% client must ignore them), as the OpenID conformance suite does.
    Junk =
        case ets:lookup(Table, junk_keys) of
            [{junk_keys, true}] ->
                [#{<<"kty">> => <<"AKP">>, <<"alg">> => <<"ML-DSA-9999">>, <<"kid">> => <<"pq">>, <<"use">> => <<"sig">>, <<"pub">> => <<"AAAA">>},
                 #{<<"kty">> => <<"MADE-UP">>, <<"kid">> => <<"made-up">>, <<"use">> => <<"sig">>}];
            _ -> []
        end,
    json(200, #{<<"keys">> => Junk ++ [Real]});
handle(Table, #{path := <<"/token">>, body := Body}) ->
    ets:update_counter(Table, token_requests, 1),
    Params = maps:from_list(uri_string:dissect_query(Body)),
    case Params of
        #{<<"grant_type">> := <<"authorization_code">>, <<"code">> := Code} ->
            case ets:take(Table, {code, Code}) of
                [{_, Nonce}] -> behave(Table, {code, Code}, Nonce);
                [] -> json(400, #{<<"error">> => <<"invalid_grant">>})
            end;
        #{<<"grant_type">> := <<"refresh_token">>, <<"refresh_token">> := Rt} ->
            case ets:take(Table, {refresh, Rt}) of
                [{_, Nonce}] ->
                    %% A response without a new refresh token leaves the
                    %% presented one valid (retain semantics).
                    %% A scripted error response does not consume the token.
                    case ets:lookup(Table, {script, {refresh, Rt}}) of
                        [{_, drop_refresh_token}] -> ets:insert(Table, {{refresh, Rt}, Nonce});
                        [{_, {status, _, _}}] -> ets:insert(Table, {{refresh, Rt}, Nonce});
                        _ -> ok
                    end,
                    behave(Table, {refresh, Rt}, Nonce);
                [] -> json(400, #{<<"error">> => <<"invalid_grant">>})
            end;
        #{<<"grant_type">> := <<"client_credentials">>} ->
            json(200, #{<<"access_token">> => rand(), <<"token_type">> => <<"Bearer">>, <<"expires_in">> => 60});
        _ ->
            json(400, #{<<"error">> => <<"unsupported_grant_type">>})
    end;
handle(Table, #{path := <<"/userinfo">>}) ->
    Default = json(200, #{<<"sub">> => <<"subject-1">>, <<"email">> => <<"user@example.test">>}),
    case ets:take(Table, {script, userinfo}) of
        [] -> Default;
        [{_, {status, Status, Error}}] -> json(Status, #{<<"error">> => Error});
        [{_, {sub, Sub}}] -> json(200, #{<<"sub">> => Sub});
        [{_, {delay, Ms}}] -> {delay, Ms, Default}
    end;
handle(_Table, #{path := <<"/introspect">>, body := Body}) ->
    case maps:from_list(uri_string:dissect_query(Body)) of
        #{<<"token">> := <<"active-token">>} ->
            json(200, #{<<"active">> => true, <<"client_id">> => ?CLIENT, <<"sub">> => <<"subject-1">>,
                        <<"scope">> => <<"openid email">>, <<"exp">> => erlang:system_time(second) + 60,
                        <<"token_type">> => <<"Bearer">>, <<"department">> => <<"platform">>});
        _ ->
            json(200, #{<<"active">> => false})
    end;
handle(_Table, _Request) ->
    json(404, #{<<"error">> => <<"not_found">>}).

behave(Table, Key, Nonce) ->
    case ets:take(Table, {script, Key}) of
        [] -> tokens(Table, Nonce, #{});
        [{_, {delay, Ms}}] -> {delay, Ms, tokens(Table, Nonce, #{})};
        [{_, {status, Status, Error}}] -> json(Status, #{<<"error">> => Error, <<"error_description">> => <<"SENTINEL-PROVIDER-DESC">>});
        [{_, close}] -> close;
        [{_, malformed_json}] -> {respond, 200, [{<<"content-type">>, <<"application/json">>}], <<"{not json">>};
        [{_, Behaviour}] -> tokens(Table, Nonce, #{behaviour => Behaviour})
    end.

tokens(Table, Nonce, Opts) ->
    Behaviour = maps:get(behaviour, Opts, none),
    Issuer = lookup(Table, issuer),
    Now = erlang:system_time(second),
    Access = rand(),
    Refresh = rand(),
    Claims0 = #{
        <<"iss">> => Issuer,
        <<"sub">> => <<"subject-1">>,
        <<"aud">> => ?CLIENT,
        <<"exp">> => Now + 300,
        <<"iat">> => Now,
        <<"auth_time">> => Now - 5,
        <<"nonce">> => Nonce,
        <<"email">> => <<"user@example.test">>,
        <<"email_verified">> => true,
        <<"department">> => <<"platform">>
    },
    Claims = maps:merge(Claims0, lookup(Table, claims)),
    IdToken =
        case Behaviour of
            {id_token, Mutation} -> mutate(Table, Claims, Mutation);
            _ -> sign(Table, Claims)
        end,
    Body0 = #{
        <<"access_token">> => Access,
        <<"token_type">> => <<"Bearer">>,
        <<"expires_in">> => 300,
        <<"refresh_token">> => Refresh,
        <<"id_token">> => IdToken,
        <<"scope">> => <<"openid profile email">>
    },
    Body1 =
        case Behaviour of
            omit_id_token -> maps:remove(<<"id_token">>, Body0);
            drop_refresh_token -> maps:remove(<<"refresh_token">>, Body0);
            _ -> Body0
        end,
    case maps:is_key(<<"refresh_token">>, Body1) of
        true -> ets:insert(Table, {{refresh, Refresh}, Nonce});
        false -> ok
    end,
    json(200, Body1).

sign(#{table := Table}, Claims) -> sign(Table, Claims);
sign(Table, Claims) ->
    [{key, Key, Kid}] = ets:lookup(Table, key),
    {_, Token} = jose_jws:compact(jose_jwt:sign(Key, #{<<"alg">> => <<"RS256">>, <<"kid">> => Kid}, Claims)),
    Token.

mutate(Table, Claims, Mutation) ->
    case Mutation of
        <<"wrong_aud">> -> sign(Table, Claims#{<<"aud">> => <<"other">>});
        <<"extra_aud">> -> sign(Table, Claims#{<<"aud">> => [?CLIENT, <<"other">>]});
        <<"wrong_azp">> -> sign(Table, Claims#{<<"azp">> => <<"other">>});
        <<"wrong_nonce">> -> sign(Table, Claims#{<<"nonce">> => <<"attacker">>});
        <<"changed_sub">> -> sign(Table, Claims#{<<"sub">> => <<"someone-else">>});
        <<"changed_nonce">> -> sign(Table, Claims#{<<"nonce">> => <<"changed">>});
        <<"changed_auth_time">> -> sign(Table, Claims#{<<"auth_time">> => 1});
        <<"expired">> -> sign(Table, Claims#{<<"exp">> => erlang:system_time(second) - 100});
        <<"unknown_kid">> ->
            Other = jose_jwk:generate_key({rsa, 2048}),
            {_, T} = jose_jws:compact(jose_jwt:sign(Other, #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"nope">>}, Claims)),
            T
    end.

json(Status, Map) ->
    {respond, Status, [{<<"content-type">>, <<"application/json">>}], json:encode(Map)}.

rand() -> base64:encode(crypto:strong_rand_bytes(24), #{mode => urlsafe, padding => false}).
