%% Total, content-free classification of foreign (oidcc) error terms.
-module(warden_oidcc_test).

-include_lib("eunit/include/eunit.hrl").

-define(S, <<"SENTINEL-SECRET-VALUE">>).

%% Every documented oidcc 3.9.0 error shape, with secret-bearing payloads.
documented_shapes() ->
    Claims = #{<<"sub">> => ?S, <<"nonce">> => ?S, <<"email">> => ?S},
    [
        {provider_not_ready, not_ready},
        {{warden_transport, not_sent, tls_rejected}, transport},
        {{warden_transport, sent, timeout}, transport},
        {{http_error, 400, #{<<"error">> => <<"invalid_grant">>, <<"error_description">> => ?S}}, endpoint},
        {{http_error, 500, ?S}, endpoint},
        {{use_dpop_nonce, ?S, ?S}, response},
        {invalid_content_type, response},
        {{invalid_json, {invalid_byte, 1, ?S}}, response},
        {{invalid_property, {access_token, ?S}}, response},
        {{missing_config_property, scopes_supported}, response},
        {{invalid_config_property, {uri, token_endpoint}}, response},
        {{issuer_mismatch, ?S}, policy},
        {{invalid_issuer, ?S}, policy},
        {no_supported_auth_method, policy},
        {pkce_verifier_required, policy},
        {no_supported_code_challenge, policy},
        {{grant_type_not_supported, refresh_token}, policy},
        {par_required, policy},
        {request_object_required, policy},
        {bad_subject, userinfo},
        {sub_invalid, id_token},
        {bad_access_token_hash, id_token},
        {token_expired, id_token},
        {token_not_yet_valid, id_token},
        {signature_required, id_token},
        {{none_alg_used, {oidcc_token, ?S, ?S, ?S, [?S]}}, id_token},
        {{none_alg_used, Claims}, id_token},
        {no_matching_key, id_token},
        {{no_matching_key_with_kid, ?S}, id_token},
        {{unsupported_signing_alg, 'HS256'}, id_token},
        {no_supported_alg_or_key, id_token},
        {invalid_jwt_token, id_token},
        {{missing_claim, {<<"nonce">>, ?S}, Claims}, id_token},
        {{missing_claim, {<<"aud">>, ?S}, Claims}, id_token},
        {{missing_claim, {<<"azp">>, [?S]}, Claims}, id_token},
        {{missing_claim, {<<"iss">>, ?S}, Claims}, id_token},
        {{missing_claim, <<"sub">>, Claims}, id_token},
        {{missing_claim, ?S, Claims}, id_token},
        {client_id_mismatch, policy},
        {introspection_not_supported, policy},
        {{something_new, ?S}, unmapped},
        {?S, unmapped}
    ].

documented_shapes_are_classified_without_content_test() ->
    lists:foreach(
        fun({Term, Kind}) ->
            Class = warden_oidcc:classify(Term),
            ?assertEqual({Term, Kind}, {Term, kind(Class)}),
            ?assertEqual(nomatch, binary:match(term_to_binary(Class), ?S)),
            Flat = flatten(Class),
            ?assertEqual(nomatch, binary:match(term_to_binary(Flat), ?S))
        end,
        documented_shapes()
    ).

kind(provider_not_ready) -> not_ready;
kind(T) when is_tuple(T) -> element(1, T).

flatten(Class) ->
    {error, Map} = warden_oidcc:contain_for_test(fun() -> {error, Class} end),
    Map.

random_terms_never_crash_classification_test() ->
    lists:foreach(
        fun(Seed) ->
            Term = warden_unit_ffi:random_term(Seed),
            Class = warden_oidcc:classify(Term),
            ?assert(closed(Class))
        end,
        lists:seq(1, 5000)
    ).

closed(provider_not_ready) -> true;
closed({transport, S, C}) -> is_atom(S) andalso is_atom(C);
closed({endpoint, Status, E}) -> is_integer(Status) andalso is_atom(E);
closed({id_token, {missing_claim, C}}) -> is_atom(C);
closed({K, D}) -> is_atom(K) andalso is_atom(D);
closed(_) -> false.

exceptions_in_operations_are_contained_test() ->
    %% A client description that makes the boundary crash internally.
    Bad = #{worker => not_a_worker, client_id => <<"c">>, auth_method => client_secret_basic,
            credential => {some, ?S}, id_token_algs => [], assertion_algs => []},
    Params = #{adapter => {warden_http, #{}}, code => ?S, redirect_uri => ?S, nonce => ?S, verifier => ?S},
    Result = warden_oidcc:exchange_code(Bad, Params),
    ?assertMatch({error, #{<<"kind">> := _}}, Result),
    ?assertEqual(nomatch, binary:match(term_to_binary(Result), ?S)).
