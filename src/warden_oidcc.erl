%% The single Erlang boundary between Warden and oidcc 3.9.0.
%%
%% Responsibilities (warden-design.md §3.4):
%% - convert Warden arguments into exact oidcc calls and options;
%% - narrow the oidcc client context to Warden's policy before every call
%%   (algorithm allowlists, exactly one client authentication method, no
%%   automatic PAR, request objects, DPoP, encrypted ID tokens or mTLS aliases);
%% - flatten oidcc records into JSON-shaped maps that Gleam decodes totally;
%% - contain exceptions and exits;
%% - classify errors by outer shape only. Embedded response bodies, claims,
%%   tokens and arbitrary terms are discarded here and never formatted.
%%
%% Every exported function returns `{ok, Value}` or `{error, Classification}`
%% where Classification is built from atoms, integers and the closed tuples
%% documented at `classify/1`.
-module(warden_oidcc).

-feature(maybe_expr, enable).

-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("oidcc/include/oidcc_token_introspection.hrl").

-export([
    adapter/5,
    client/6,
    load_metadata/2,
    start_worker/3,
    stop_worker/1,
    ready/1,
    metadata/1,
    authorization_url/2,
    exchange_code/2,
    refresh/2,
    userinfo/2,
    introspect/2,
    client_credentials/2,
    logout_url/2,
    classify/1,
    params/1
]).

%% Parameter map from Gleam `[{Key, Value}]`. Keys come from a fixed list so
%% no request-derived string is ever converted to an atom.
params(Entries) ->
    maps:from_list([{param_key(K), V} || {K, V} <- Entries]).

param_key(<<"adapter">>) -> adapter;
param_key(<<"redirect_uri">>) -> redirect_uri;
param_key(<<"state">>) -> state;
param_key(<<"nonce">>) -> nonce;
param_key(<<"verifier">>) -> verifier;
param_key(<<"scopes">>) -> scopes;
param_key(<<"response_mode">>) -> response_mode;
param_key(<<"extension">>) -> extension;
param_key(<<"code">>) -> code;
param_key(<<"refresh_token">>) -> refresh_token;
param_key(<<"expected_subject">>) -> expected_subject;
param_key(<<"access_token">>) -> access_token;
param_key(<<"token">>) -> token;
param_key(<<"id_token_hint">>) -> id_token_hint;
param_key(<<"post_logout_redirect_uri">>) -> post_logout_redirect_uri.

%% ---------------------------------------------------------------------------
%% Construction (trusted startup)

%% Transport adapter configuration for `warden_http`.
adapter(Trust, Destinations, AllowedHosts, TimeoutMs, MaxBody) ->
    Cacerts =
        case Trust of
            system_anchors -> system;
            {certificate_anchors, Ders} -> Ders
        end,
    {AllowLoopback, AllowPrivate} =
        case Destinations of
            public_internet_only -> {false, false};
            allow_loopback_for_testing -> {true, false};
            allow_private_network -> {false, true}
        end,
    Hosts =
        case AllowedHosts of
            none -> any;
            {some, List} -> List
        end,
    {warden_http, #{
        cacerts => Cacerts,
        allow_loopback => AllowLoopback,
        allow_private => AllowPrivate,
        allowed_hosts => Hosts,
        timeout => TimeoutMs,
        max_body => MaxBody
    }}.

%% Client description used by every operation. `Credential` is
%% `{some, SecretOrJwkJson}` or `none`.
client(Worker, ClientId, AuthMethod, Credential, IdTokenAlgs, AssertionAlgs) ->
    #{
        worker => Worker,
        client_id => ClientId,
        auth_method => binary_to_atom(AuthMethod),
        credential => Credential,
        id_token_algs => IdTokenAlgs,
        assertion_algs => AssertionAlgs
    }.

%% ---------------------------------------------------------------------------
%% Provider worker

%% Discovery through the Warden adapter, returning a flattened summary. Used
%% at startup to obtain a typed failure before the worker is started.
load_metadata(Issuer, Adapter) ->
    contain(fun() ->
        case
            oidcc_provider_configuration:load_configuration(Issuer, #{
                request_opts => #{http_adapter => Adapter}
            })
        of
            {ok, {Configuration, _Expiry}} -> {ok, summary(Configuration)};
            {error, Reason} -> {error, classify(Reason)}
        end
    end).

%% Start the oidcc provider worker, registered under `Name` (an atom allocated
%% once at trusted startup), unlinked from the caller: Warden's supervisor
%% owns it through `start_link` in the child spec.
start_worker(Name, Issuer, Adapter) ->
    contain(fun() ->
        case
            oidcc_provider_configuration_worker:start_link(#{
                issuer => Issuer,
                name => {local, Name},
                provider_configuration_opts => #{request_opts => #{http_adapter => Adapter}},
                backoff_type => random_exponential,
                backoff_min => 1000,
                backoff_max => 60000
            })
        of
            {ok, Pid} -> {ok, Pid};
            {error, _} -> {error, worker_start_failed};
            ignore -> {error, worker_start_failed}
        end
    end).

stop_worker(Name) ->
    case whereis(Name) of
        undefined -> nil;
        Pid -> exit(Pid, shutdown), nil
    end.

ready(Name) ->
    try
        case whereis(Name) of
            undefined ->
                false;
            _ ->
                oidcc_provider_configuration_worker:get_provider_configuration(Name) =/= undefined andalso
                    oidcc_provider_configuration_worker:get_jwks(Name) =/= undefined
        end
    catch
        _:_ -> false
    end.

metadata(Name) ->
    contain(fun() ->
        case whereis(Name) of
            undefined ->
                {error, provider_not_ready};
            _ ->
                case oidcc_provider_configuration_worker:get_provider_configuration(Name) of
                    #oidcc_provider_configuration{} = C -> {ok, summary(C)};
                    _ -> {error, provider_not_ready}
                end
        end
    end).

summary(#oidcc_provider_configuration{} = C) ->
    #{
        <<"issuer">> => C#oidcc_provider_configuration.issuer,
        <<"authorization_endpoint">> => bin(C#oidcc_provider_configuration.authorization_endpoint),
        <<"token_endpoint">> => opt(C#oidcc_provider_configuration.token_endpoint),
        <<"userinfo_endpoint">> => opt(C#oidcc_provider_configuration.userinfo_endpoint),
        <<"introspection_endpoint">> => opt(C#oidcc_provider_configuration.introspection_endpoint),
        <<"end_session_endpoint">> => opt(C#oidcc_provider_configuration.end_session_endpoint),
        <<"code_challenge_methods_supported">> => list(C#oidcc_provider_configuration.code_challenge_methods_supported),
        <<"grant_types_supported">> => list(C#oidcc_provider_configuration.grant_types_supported),
        <<"response_modes_supported">> => list(C#oidcc_provider_configuration.response_modes_supported),
        <<"token_endpoint_auth_methods_supported">> => list(C#oidcc_provider_configuration.token_endpoint_auth_methods_supported),
        <<"token_endpoint_auth_signing_alg_values_supported">> => list(C#oidcc_provider_configuration.token_endpoint_auth_signing_alg_values_supported),
        <<"id_token_signing_alg_values_supported">> => list(C#oidcc_provider_configuration.id_token_signing_alg_values_supported),
        <<"authorization_response_iss_parameter_supported">> => C#oidcc_provider_configuration.authorization_response_iss_parameter_supported =:= true,
        <<"require_pushed_authorization_requests">> => C#oidcc_provider_configuration.require_pushed_authorization_requests =:= true,
        <<"require_signed_request_object">> => C#oidcc_provider_configuration.require_signed_request_object =:= true
    }.

bin(undefined) -> <<>>;
bin(V) -> iolist_to_binary(V).
opt(undefined) -> null;
opt(V) -> iolist_to_binary(V).
list(undefined) -> [];
list(L) when is_list(L) -> [iolist_to_binary(X) || X <- L, is_binary(X) orelse is_list(X)];
list(_) -> [].

%% ---------------------------------------------------------------------------
%% Client context narrowing

context(#{worker := Worker, client_id := ClientId, credential := Credential, auth_method := Method} = Client) ->
    %% oidcc keys the method choice on the secret slot: `unauthenticated` for a
    %% public client; a binary otherwise. For private_key_jwt the slot carries
    %% no secret, and because HMAC ID-token algorithms are never allowed it is
    %% never turned into a verification key.
    {SecretSlot, ContextOpts} =
        case {Method, Credential} of
            {none, _} -> {unauthenticated, #{}};
            {private_key_jwt, {some, Json}} -> {<<"private-key-jwt">>, #{client_jwks => jose_jwk:from_map(json:decode(Json))}};
            {_, {some, Secret}} -> {Secret, #{}}
        end,
    case oidcc_client_context:from_configuration_worker(Worker, ClientId, SecretSlot, ContextOpts) of
        {ok, Context} -> {ok, narrow(Context, Client)};
        {error, provider_not_ready} -> {error, provider_not_ready}
    end.

narrow(#oidcc_client_context{provider_configuration = C} = Context, Client) ->
    IdAlgs = intersect(C#oidcc_provider_configuration.id_token_signing_alg_values_supported, maps:get(id_token_algs, Client)),
    AssertionAlgs = intersect(
        C#oidcc_provider_configuration.token_endpoint_auth_signing_alg_values_supported,
        maps:get(assertion_algs, Client)
    ),
    IntrospectionAlgs = intersect(
        C#oidcc_provider_configuration.introspection_endpoint_auth_signing_alg_values_supported,
        maps:get(assertion_algs, Client)
    ),
    UserinfoAlgs = intersect(C#oidcc_provider_configuration.userinfo_signing_alg_values_supported, maps:get(id_token_algs, Client)),
    Context#oidcc_client_context{
        provider_configuration = C#oidcc_provider_configuration{
            id_token_signing_alg_values_supported = IdAlgs,
            id_token_encryption_alg_values_supported = undefined,
            id_token_encryption_enc_values_supported = undefined,
            userinfo_signing_alg_values_supported = UserinfoAlgs,
            userinfo_encryption_alg_values_supported = undefined,
            userinfo_encryption_enc_values_supported = undefined,
            token_endpoint_auth_signing_alg_values_supported = AssertionAlgs,
            introspection_endpoint_auth_signing_alg_values_supported = IntrospectionAlgs,
            pushed_authorization_request_endpoint = undefined,
            request_parameter_supported = false,
            request_object_signing_alg_values_supported = undefined,
            request_object_encryption_alg_values_supported = undefined,
            request_object_encryption_enc_values_supported = undefined,
            authorization_signing_alg_values_supported = undefined,
            authorization_encryption_alg_values_supported = undefined,
            authorization_encryption_enc_values_supported = undefined,
            dpop_signing_alg_values_supported = undefined,
            mtls_endpoint_aliases = #{},
            %% Metadata cannot widen what Warden sends: exactly one method.
            token_endpoint_auth_methods_supported = [atom_to_binary(maps:get(auth_method, Client))],
            introspection_endpoint_auth_methods_supported = [atom_to_binary(maps:get(auth_method, Client))]
        }
    }.

intersect(undefined, _Allowed) -> [];
intersect(Advertised, Allowed) when is_list(Advertised) ->
    [A || A <- Allowed, lists:member(A, Advertised), A =/= <<"none">>].

%% Options common to requests: exact auth method, Warden transport.
base_opts(Client, Adapter) ->
    #{
        preferred_auth_methods => [maps:get(auth_method, Client)],
        request_opts => #{http_adapter => Adapter}
    }.

%% ---------------------------------------------------------------------------
%% Operations

%% Authorization URL. `Params` carries state, nonce, verifier, scopes,
%% redirect URI, response mode and validated extension parameters.
authorization_url(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter} = Params,
            Opts0 = (base_opts(Client, Adapter))#{
                redirect_uri => maps:get(redirect_uri, Params),
                state => maps:get(state, Params),
                nonce => maps:get(nonce, Params),
                pkce_verifier => maps:get(verifier, Params),
                require_pkce => true,
                scopes => maps:get(scopes, Params),
                url_extension => maps:get(extension, Params)
            },
            Opts =
                case maps:get(response_mode, Params) of
                    <<"query">> -> Opts0;
                    Mode -> Opts0#{response_mode => Mode}
                end,
            case oidcc_authorization:create_redirect_url(Context, Opts) of
                {ok, Url} -> {ok, iolist_to_binary(Url)};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

%% Authorization-code exchange with Warden's verification profile: retained
%% redirect URI, nonce and verifier; PKCE required; strict audience; azp
%% equal to the client when present. The ID token is required by the caller.
exchange_code(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter, code := Code} = Params,
            Opts = (base_opts(Client, Adapter))#{
                redirect_uri => maps:get(redirect_uri, Params),
                nonce => maps:get(nonce, Params),
                pkce_verifier => maps:get(verifier, Params),
                require_pkce => true,
                trusted_audiences => [],
                validate_azp => client_id,
                refresh_jwks => oidcc_jwt_util:refresh_jwks_fun(maps:get(worker, Client))
            },
            case oidcc_token:retrieve(Code, Context, Opts) of
                {ok, Token} -> {ok, flatten_token(Token)};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

refresh(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter, refresh_token := RefreshToken, expected_subject := Subject} = Params,
            Opts = (base_opts(Client, Adapter))#{
                expected_subject => Subject,
                trusted_audiences => [],
                validate_azp => client_id,
                refresh_jwks => oidcc_jwt_util:refresh_jwks_fun(maps:get(worker, Client))
            },
            case oidcc_token:refresh(RefreshToken, Context, Opts) of
                {ok, Token} -> {ok, flatten_token(Token)};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

userinfo(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter, access_token := AccessToken, expected_subject := Subject} = Params,
            Opts = #{expected_subject => Subject, request_opts => #{http_adapter => Adapter}},
            case oidcc_userinfo:retrieve(AccessToken, Context, Opts) of
                {ok, Claims} ->
                    case json_claims(Claims) of
                        {ok, Checked} -> {ok, Checked};
                        error -> {error, {response, malformed}}
                    end;
                {error, Reason} ->
                    {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

introspect(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter, token := Token} = Params,
            Opts = (base_opts(Client, Adapter))#{client_self_only => false},
            case oidcc_token_introspection:introspect(Token, Context, Opts) of
                {ok, #oidcc_token_introspection{active = true} = I} -> {ok, flatten_introspection(I)};
                {ok, #oidcc_token_introspection{}} -> {ok, #{<<"active">> => false}};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

client_credentials(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            #{adapter := Adapter, scopes := Scopes} = Params,
            Opts = (base_opts(Client, Adapter))#{
                scope => Scopes,
                refresh_jwks => oidcc_jwt_util:refresh_jwks_fun(maps:get(worker, Client))
            },
            case oidcc_token:client_credentials(Context, Opts) of
                {ok, Token} -> {ok, flatten_token(Token)};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

logout_url(Client, Params) ->
    contain(fun() ->
        maybe
            {ok, Context} ?= context(Client),
            Hint =
                case maps:get(id_token_hint, Params) of
                    {some, IdToken} -> IdToken;
                    none -> undefined
                end,
            Opts0 = #{},
            Opts1 =
                case maps:get(post_logout_redirect_uri, Params) of
                    {some, Uri} -> Opts0#{post_logout_redirect_uri => Uri};
                    none -> Opts0
                end,
            Opts =
                case maps:get(state, Params) of
                    {some, State} -> Opts1#{state => State};
                    none -> Opts1
                end,
            case oidcc_logout:initiate_url(Hint, Context, Opts) of
                {ok, Url} -> {ok, iolist_to_binary(Url)};
                {error, Reason} -> {error, classify(Reason)}
            end
        else
            {error, R} -> {error, classify(R)}
        end
    end).

%% ---------------------------------------------------------------------------
%% Flattening

flatten_token(#oidcc_token{id = Id, access = Access, refresh = Refresh, scope = Scope}) ->
    IdPart =
        case Id of
            #oidcc_token_id{token = IdToken, claims = Claims} ->
                case json_claims(Claims) of
                    {ok, Checked} -> #{<<"id_token">> => IdToken, <<"claims">> => Checked};
                    error -> #{<<"id_token_malformed">> => true}
                end;
            none ->
                #{}
        end,
    AccessPart =
        case Access of
            #oidcc_token_access{token = At, expires = Expires, type = Type} ->
                #{
                    <<"access_token">> => At,
                    <<"expires_in">> => case Expires of
                        E when is_integer(E) -> E;
                        _ -> null
                    end,
                    <<"token_type">> => case Type of
                        T when is_binary(T) -> T;
                        _ -> <<"Bearer">>
                    end
                };
            none ->
                #{}
        end,
    RefreshPart =
        case Refresh of
            #oidcc_token_refresh{token = Rt} when is_binary(Rt) -> #{<<"refresh_token">> => Rt};
            _ -> #{}
        end,
    Scopes = [S || S <- scope_list(Scope), is_binary(S)],
    maps:merge(maps:merge(IdPart, AccessPart), RefreshPart#{<<"scope">> => Scopes}).

scope_list(L) when is_list(L) -> [iolist_to_binary(S) || S <- L, is_binary(S) orelse is_list(S)];
scope_list(_) -> [].

flatten_introspection(#oidcc_token_introspection{} = I) ->
    Base = #{
        <<"active">> => true,
        <<"client_id">> => nullable(I#oidcc_token_introspection.client_id),
        <<"exp">> => int_or_null(I#oidcc_token_introspection.exp),
        <<"iat">> => int_or_null(I#oidcc_token_introspection.iat),
        <<"scope">> => scope_list(I#oidcc_token_introspection.scope),
        <<"sub">> => nullable(I#oidcc_token_introspection.sub),
        <<"username">> => nullable(I#oidcc_token_introspection.username),
        <<"token_type">> => nullable(I#oidcc_token_introspection.token_type),
        <<"iss">> => nullable(I#oidcc_token_introspection.iss)
    },
    Extra =
        case json_claims(I#oidcc_token_introspection.extra) of
            {ok, E} -> E;
            error -> #{}
        end,
    Base#{<<"extra">> => Extra}.

nullable(V) when is_binary(V) -> V;
nullable(_) -> null.
int_or_null(V) when is_integer(V) -> V;
int_or_null(_) -> null.

json_claims(Claims) when is_map(Claims) ->
    case warden_ffi:is_json_term(Claims) of
        true -> {ok, Claims};
        false -> error
    end;
json_claims(_) ->
    error.

%% ---------------------------------------------------------------------------
%% Containment and classification

contain(Fun) ->
    Result =
        try
            Fun()
        catch
            _:_ -> {error, {unmapped, backend_exception}}
        end,
    case Result of
        {ok, _} = Ok -> Ok;
        {error, Class} -> {error, flatten_error(Class)};
        _ -> {error, flatten_error({unmapped, unexpected_result})}
    end.

%% A classification as a map of binaries (and an integer status), so the
%% Gleam side decodes it without atom handling.
flatten_error(provider_not_ready) -> #{<<"kind">> => <<"not_ready">>};
flatten_error({transport, Stage, Class}) ->
    #{<<"kind">> => <<"transport">>, <<"stage">> => atom_to_binary(Stage), <<"detail">> => atom_to_binary(Class)};
flatten_error({endpoint, Status, Error}) ->
    #{<<"kind">> => <<"endpoint">>, <<"status">> => Status, <<"detail">> => atom_to_binary(Error)};
flatten_error({id_token, {missing_claim, Claim}}) ->
    #{<<"kind">> => <<"id_token">>, <<"detail">> => <<"missing_claim">>, <<"claim">> => atom_to_binary(Claim)};
flatten_error({Kind, Detail}) when is_atom(Kind), is_atom(Detail) ->
    #{<<"kind">> => atom_to_binary(Kind), <<"detail">> => atom_to_binary(Detail)};
flatten_error(_) ->
    #{<<"kind">> => <<"unmapped">>, <<"detail">> => <<"unknown">>}.

%% Classification is by outer shape only. Results:
%%   provider_not_ready
%%   {transport, not_sent | sent, Class}
%%   {endpoint, Status, OAuthError}          OAuthError :: known atom | other
%%   {response, malformed | invalid_content_type | dpop_nonce}
%%   {id_token, Reason}                      Reason :: see id_token_reason/1
%%   {policy, Reason}                        failures before any request
%%   {userinfo, subject_mismatch}
%%   {unmapped, Tag}
classify(provider_not_ready) -> provider_not_ready;
classify({warden_transport, Stage, Class}) when is_atom(Stage), is_atom(Class) -> {transport, Stage, Class};
classify({http_error, Status, Body}) when is_integer(Status) -> {endpoint, Status, oauth_error(Body)};
classify({use_dpop_nonce, _, _}) -> {response, dpop_nonce};
classify(invalid_content_type) -> {response, invalid_content_type};
classify({invalid_json, _}) -> {response, malformed};
classify({invalid_property, _}) -> {response, malformed};
classify({issuer_mismatch, _}) -> {policy, issuer_mismatch};
classify({invalid_issuer, _}) -> {policy, invalid_issuer};
classify({invalid_document, _}) -> {response, malformed};
classify(no_supported_auth_method) -> {policy, auth_method_unsupported};
classify(pkce_verifier_required) -> {policy, pkce_unsupported};
classify(no_supported_code_challenge) -> {policy, pkce_unsupported};
classify({grant_type_not_supported, _}) -> {policy, grant_unsupported};
classify(par_required) -> {policy, par_required};
classify(request_object_required) -> {policy, request_object_required};
classify(bad_subject) -> {userinfo, subject_mismatch};
classify(no_access_token) -> {policy, no_access_token};
classify(introspection_not_supported) -> {policy, endpoint_missing};
classify(client_id_mismatch) -> {policy, client_mismatch};
classify({distributed_claim_not_found, _}) -> {response, malformed};
classify(Reason) ->
    case id_token_reason(Reason) of
        unknown -> {unmapped, unknown};
        R -> {id_token, R}
    end.

id_token_reason(sub_invalid) -> subject_mismatch;
id_token_reason(bad_access_token_hash) -> access_token_hash;
id_token_reason(token_expired) -> expired;
id_token_reason(token_not_yet_valid) -> not_yet_valid;
id_token_reason(signature_required) -> encrypted_unsigned;
id_token_reason({none_alg_used, _}) -> alg_none;
id_token_reason(none_alg_used) -> alg_none;
id_token_reason({none_alg_used, _, _}) -> alg_none;
id_token_reason(no_matching_key) -> bad_signature;
id_token_reason({no_matching_key_with_kid, _}) -> unknown_key;
id_token_reason({unsupported_signing_alg, _}) -> unsupported_algorithm;
id_token_reason(no_supported_alg_or_key) -> encrypted_unsupported;
id_token_reason(invalid_jwt_token) -> malformed;
id_token_reason(not_encrypted) -> malformed;
id_token_reason({missing_claim, {<<"iss">>, _}, _}) -> issuer_mismatch;
id_token_reason({missing_claim, {<<"aud">>, _}, _}) -> audience_mismatch;
id_token_reason({missing_claim, {<<"azp">>, _}, _}) -> authorized_party_mismatch;
id_token_reason({missing_claim, {<<"nonce">>, _}, _}) -> nonce_mismatch;
id_token_reason({missing_claim, {_, _}, _}) -> claim_mismatch;
id_token_reason({missing_claim, Name, _}) when is_binary(Name) ->
    case Name of
        <<"iss">> -> {missing_claim, iss};
        <<"sub">> -> {missing_claim, sub};
        <<"aud">> -> {missing_claim, aud};
        <<"exp">> -> {missing_claim, exp};
        <<"iat">> -> {missing_claim, iat};
        _ -> {missing_claim, other}
    end;
id_token_reason(_) -> unknown.

oauth_error(#{<<"error">> := Error}) when is_binary(Error) ->
    case Error of
        <<"invalid_request">> -> invalid_request;
        <<"invalid_client">> -> invalid_client;
        <<"invalid_grant">> -> invalid_grant;
        <<"unauthorized_client">> -> unauthorized_client;
        <<"unsupported_grant_type">> -> unsupported_grant_type;
        <<"invalid_scope">> -> invalid_scope;
        <<"invalid_token">> -> invalid_token;
        <<"insufficient_scope">> -> insufficient_scope;
        <<"invalid_dpop_proof">> -> invalid_dpop_proof;
        _ -> other
    end;
oauth_error(_) ->
    none.
