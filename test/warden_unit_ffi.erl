-module(warden_unit_ffi).
-export([random_query/1, random_term/1]).

%% Random query-like strings mixing valid and hostile fragments.
random_query(Seed) ->
    rand:seed(exsss, {Seed, Seed * 7, Seed * 13}),
    Parts = [<<"code=">>, <<"state=">>, <<"iss=">>, <<"error=">>, <<"&">>, <<"=">>, <<"%">>, <<"%2">>,
             <<"%41">>, <<"+">>, <<"x">>, <<"abc">>, <<"%00">>, <<"%0A">>, <<"\"">>, <<"&&">>,
             <<"code=a&state=b">>, <<226, 130, 172>>],
    N = rand:uniform(12),
    iolist_to_binary([lists:nth(rand:uniform(length(Parts)), Parts) || _ <- lists:seq(1, N)]).

%% Random Erlang terms for foreign-decoding fuzzing.
random_term(Seed) ->
    rand:seed(exsss, {Seed, Seed + 1, Seed + 2}),
    term(3).

term(0) -> leaf();
term(D) ->
    case rand:uniform(6) of
        1 -> leaf();
        2 -> [term(D - 1) || _ <- lists:seq(1, rand:uniform(3))];
        3 -> list_to_tuple([term(D - 1) || _ <- lists:seq(1, rand:uniform(4))]);
        4 -> maps:from_list([{leaf(), term(D - 1)} || _ <- lists:seq(1, rand:uniform(3))]);
        5 -> #{<<"kind">> => lists:nth(rand:uniform(8), [<<"transport">>, <<"endpoint">>, <<"id_token">>, <<"policy">>, <<"not_ready">>, <<"response">>, 42, x]), <<"detail">> => leaf(), <<"stage">> => leaf(), <<"status">> => leaf()};
        6 -> {error, term(D - 1)}
    end.

leaf() ->
    lists:nth(rand:uniform(10), [ok, error, nil, 0, -1, 3.5, <<"x">>, <<"sent">>, self(), make_ref()]).
