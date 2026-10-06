-module(warden_test_runner_test).
-include_lib("eunit/include/eunit.hrl").

unknown_suite_is_rejected_test() ->
    ?assertEqual({error, {unknown_suite, "typo"}}, warden_test_runner:select("typo", ["warden_test.gleam"])).

empty_suite_is_rejected_test() ->
    ?assertEqual({error, {empty_suite, "node"}}, warden_test_runner:select("node", ["warden_test.gleam"])).

helper_only_suite_is_rejected_test() ->
    ?assertEqual({error, {empty_suite, "node"}}, warden_test_runner:select("node", ["integration/node/node_raw_ffi.erl"])).

provider_selection_does_not_include_fast_or_other_providers_test() ->
    Files = ["warden_test.gleam", "integration/node/node_warden_test.gleam", "integration/keycloak/keycloak_login_test.gleam"],
    ?assertEqual({ok, ["integration/node/node_warden_test.gleam"]}, warden_test_runner:select("node", Files)).

fast_selection_excludes_provider_tests_test() ->
    ?assertEqual({ok, ["warden_test.gleam"]}, warden_test_runner:select("fast", ["warden_test.gleam", "integration/node/node_warden_test.gleam"])).
