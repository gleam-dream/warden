%% Raw oidcc 3.9.0 baseline for the differential corpus: a typical direct
%% use of the oidcc facade with the options an application would pass
%% (redirect URI, nonce, PKCE verifier, one client-auth method) and oidcc's
%% defaults for everything else. Transport is Warden's adapter so that only
%% protocol policy differs.
-module(node_raw_ffi).
-export([raw_login/2]).

-define(ISSUER, <<"https://localhost:19443">>).
-define(REDIRECT, <<"https://localhost:1/callback">>).

adapter() ->
    warden_test_support:test_adapter(10000).

rand() -> base64:encode(crypto:strong_rand_bytes(32), #{mode => urlsafe, padding => false}).

%% Mutation: an ID-token mutation name, `<<"omit">>` or `<<"none">>`.
raw_login(Mutation, _Unused) ->
    {ok, _} = application:ensure_all_started([oidcc, inets, ssl]),
    Name = list_to_atom("warden_raw_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => ?ISSUER, name => {local, Name},
        provider_configuration_opts => #{request_opts => #{http_adapter => adapter()}}
    }),
    unlink(Pid),
    wait(Name, 100),
    Common = #{preferred_auth_methods => [client_secret_basic], request_opts => #{http_adapter => adapter()}},
    Secret = <<"warden-node-disposable-secret-0123456789">>,
    Nonce = rand(), Verifier = rand(), State = rand(),
    {ok, Url} = oidcc:create_redirect_url(Name, <<"warden-rp">>, Secret, Common#{
        redirect_uri => ?REDIRECT, nonce => Nonce, state => State, pkce_verifier => Verifier,
        scopes => [openid, <<"email">>, <<"profile">>], url_extension => [{<<"login_hint">>, <<"alice">>}]}),
    case Mutation of
        <<"none">> -> ok;
        <<"omit">> -> warden_test_support_ffi:node_next(<<"authorization_code">>, [node_omit_id_token]);
        M -> warden_test_support_ffi:node_next(<<"authorization_code">>, [{node_id_token, M}])
    end,
    {{query, Query}, _} = warden_test_browser:authorize(warden_test_browser:new(), iolist_to_binary(Url), ?ISSUER),
    #{<<"code">> := Code} = maps:from_list(uri_string:dissect_query(Query)),
    Result = oidcc:retrieve_token(Code, Name, <<"warden-rp">>, Secret, Common#{
        redirect_uri => ?REDIRECT, nonce => Nonce, pkce_verifier => Verifier}),
    exit(Pid, shutdown),
    case Result of
        {ok, _} -> <<"accepted">>;
        {error, Reason} ->
            {Kind, Detail} = warden_oidcc:classify(Reason),
            iolist_to_binary(["rejected:", atom_to_list(Kind), ":", io_lib:format("~p", [Detail])])
    end.

wait(_, 0) -> error(not_ready);
wait(Name, N) ->
    case catch oidcc_provider_configuration_worker:get_jwks(Name) of
        undefined -> timer:sleep(50), wait(Name, N - 1);
        {'EXIT', _} -> timer:sleep(50), wait(Name, N - 1);
        _ -> ok
    end.
