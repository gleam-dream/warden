%% Lifecycle regressions use real TLS, OTP supervision and public validation.
%% Telemetry handlers deliberately stop a worker after the HTTP response so
%% owner loss cannot be hidden by HTTP Gun cancelling its own request.
-module(warden_fetch_ownership_test).
-include_lib("eunit/include/eunit.hrl").
-export([observe/4, benchmark/0, snapshot_benchmark/0, hold_tree/4]).

stale_completion_cannot_restore_removed_key_test() ->
    with_client(fun(Test, Client, Parent, Handle) ->
        Token = token(Test),
        Validator = warden@resource:new(Client, <<"https://api.test">>),
        ?assertMatch({ok, _}, warden@resource:verify(Validator, Token)),
        with_barrier(fun(Id) ->
            Caller = refresh(Handle, <<"rotation">>),
            Worker = blocked(),
            warden@testing:rotate_signing_key(Test),
            warden@testing:rotate_signing_key(Test),
            Cache = cache(Parent),
            stop(Cache, kill),
            Replacement = next_worker(),
            complete(Parent, Replacement),
            ?assertEqual({error, unknown_signing_key}, warden@resource:verify(Validator, Token)),
            Worker ! release,
            down(Worker, 1000),
            ?assertEqual({error, unknown_signing_key}, warden@resource:verify(Validator, Token)),
            result(Caller),
            telemetry:detach(Id)
        end)
    end).

owner_exit_stops_post_response_worker_test() ->
    lists:foreach(fun(Reason) ->
        with_client(fun(_, _, Parent, Handle) ->
            with_barrier(fun(_) ->
                Caller = refresh(Handle, <<"owner-exit">>),
                Worker = blocked(),
                stop(cache(Parent), Reason),
                ?assert(lists:member(down(Worker, 500), [killed, noproc])),
                result(Caller)
            end)
        end)
    end, [kill, shutdown]).

client_shutdown_stops_post_response_worker_test() ->
    with_client(fun(_, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"shutdown">>),
            Worker = blocked(),
            stop(Parent, shutdown),
            ?assert(lists:member(down(Worker, 500), [killed, noproc])),
            result(Caller)
        end)
    end).

worker_loss_releases_waiters_and_retains_snapshot_test() ->
    with_client(fun(Test, Client, _, Handle) ->
        Validator = warden@resource:new(Client, <<"https://api.test">>),
        Token = token(Test),
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"lost-worker">>),
            Worker = blocked(),
            stop(Worker, kill),
            ?assertMatch({ok, _}, result(Caller, 500)),
            ?assertMatch({ok, _}, warden@resource:verify(Validator, Token)),
            Next = refresh(Handle, <<"next-worker">>),
            Fresh = next_worker(),
            Fresh ! release,
            down(Fresh, 5000),
            ?assertMatch({ok, _}, result(Next))
        end)
    end).

cached_reads_and_independent_client_progress_test() ->
    with_client(fun(Test, Client, _, Handle) ->
        with_client(fun(Other, OtherClient, _, _) ->
            with_barrier(fun(_) ->
                Caller = refresh(Handle, <<"slow">>),
                Worker = blocked(),
                ?assertMatch({ok, _}, warden@resource:verify(
                    warden@resource:new(Client, <<"https://api.test">>), token(Test))),
                ?assertMatch({ok, _}, warden@resource:verify(
                    warden@resource:new(OtherClient, <<"https://api.test">>), token(Other))),
                Worker ! release,
                ?assertMatch({ok, _}, result(Caller))
            end)
        end)
    end).

with_client(Fun) -> with_configured_client(fun(Config) -> Config end, Fun).

with_configured_client(Configure, Fun) ->
    {ok, _} = application:ensure_all_started(warden),
    {ok, Test} = warden@testing:start_provider(warden@testing:provider_options()),
    try
        {ok, Client} = warden:new(Configure(warden@testing:config(Test, <<"https://app.test/callback">>))),
        Id = make_ref(),
        ok = telemetry:attach(Id, [warden, http, request], fun ?MODULE:observe/4,
                              {watch, self(), Id}),
        Builder = gleam@otp@static_supervisor:new(one_for_one),
        {ok, {started, Parent, _}} = gleam@otp@static_supervisor:start(
            gleam@otp@static_supervisor:add(Builder, warden:supervised(Client))),
        unlink(Parent),
        try
            Worker = next_worker(Id),
            complete(Parent, Worker),
            telemetry:detach(Id),
            {registered_name, Name} = process_info(cache(Parent), registered_name),
            Handle = {provider, {named_subject, Name}, 5000},
            await_ready(Handle, erlang:monotonic_time(millisecond) + 5000),
            Fun(Test, Client, Parent, Handle)
        after
            telemetry:detach(Id),
            stop(Parent, shutdown)
        end
    after warden@testing:stop_provider(Test) end.

await_ready(Handle, Deadline) ->
    case warden@internal@native@provider:snapshot_of(Handle) of
        {ok, _} -> ok;
        {error, not_ready} ->
            ?assert(erlang:monotonic_time(millisecond) < Deadline),
            await_ready(Handle, Deadline)
    end.

cache(Parent) ->
    [{_, Warden, supervisor, _}] = supervisor:which_children(Parent),
    [Cache] = [Pid || {_, Pid, _, _} <- supervisor:which_children(Warden),
        {registered_name, Name} <- [process_info(Pid, registered_name)],
        lists:prefix("warden_provider", atom_to_list(Name))],
    Cache.

token(Test) ->
    Spec = warden@testing:with_audiences(warden@testing:access_token(<<"ada">>),
                                       [<<"https://api.test">>]),
    warden@testing:issue_access_token(Test, Spec).

with_barrier(Fun) ->
    Id = make_ref(),
    Previous = put(ownership_observation, Id),
    Workers = ets:new(workers, [public, set]),
    ok = telemetry:attach(Id, [warden, http, request], fun ?MODULE:observe/4,
                          {hold, self(), atomics:new(1, []), Workers, Id}),
    try Fun(Id)
    after
        telemetry:detach(Id),
        [exit(Pid, kill) || {Pid} <- ets:tab2list(Workers)],
        ets:delete(Workers),
        put(ownership_observation, Previous)
    end.

observe(_, _, Meta, {network, Parent, Id}) ->
    case maps:get(path, Meta, <<>>) of
        <<"/.well-known/openid-configuration">> -> Parent ! {Id, network_worker, self()};
        _ -> ok
    end;
observe(_, _, Meta, Mode) ->
    case maps:get(path, Meta, <<>>) of
        <<"/jwks">> -> observe(Mode);
        _ -> ok
    end.
observe({watch, Parent, Id}) -> Parent ! {Id, fetch_worker, self()}, hold();
observe({hold, Parent, Count, Workers, Id}) ->
    ets:insert(Workers, {self()}),
    case atomics:add_get(Count, 1, 1) of
        1 -> Parent ! {Id, blocked_worker, self()}, hold();
        _ -> Parent ! {Id, fetch_worker, self()}
    end.

hold() -> receive release -> ok after 10000 -> error(barrier_timeout) end.

%% Observe the real lifecycle boundary, including any completion-forwarding
%% process. No actor state tuple or application message is inspected.
complete(Parent, Worker) ->
    {monitors, Monitors} = process_info(cache(Parent), monitors),
    Worker ! release,
    down(Worker, 5000),
    [down(Pid, 5000) || {process, Pid} <- Monitors].

refresh(Handle, Kid) ->
    Parent = self(),
    Ref = make_ref(),
    spawn(fun() -> Parent ! {Ref, warden@internal@native@provider:refresh_keys(Handle, {some, Kid})} end),
    Ref.
result(Ref) -> result(Ref, 6000).
result(Ref, Timeout) ->
    receive {Ref, Result} -> Result after Timeout -> error(refresh_did_not_return) end.
blocked() ->
    Id = get(ownership_observation),
    receive {Id, blocked_worker, Pid} -> Pid after 5000 -> error(no_blocked_worker) end.
next_worker() -> next_worker(get(ownership_observation)).
next_worker(Id) -> receive {Id, fetch_worker, Pid} -> Pid after 5000 -> error(no_fetch_worker) end.
down(Pid, Timeout) ->
    Ref = monitor(process, Pid),
    receive {'DOWN', Ref, process, Pid, Reason} -> Reason
    after Timeout -> demonitor(Ref, [flush]), error({worker_still_alive, Pid}) end.
stop(Pid, Reason) ->
    Ref = monitor(process, Pid),
    case Reason of normal -> catch sys:terminate(Pid, normal, 5000); _ -> exit(Pid, Reason) end,
    receive {'DOWN', Ref, process, Pid, _} -> ok after 6000 -> error(owner_did_not_stop) end.

%% Fixed local microbenchmark, deliberately outside the correctness gate.
benchmark() ->
    lists:foreach(fun(N) -> bench_clients(N, [], fun bench/1) end, [1, 4]),
    bookkeeping().
bench_clients(0, Acc, Fun) -> Fun(Acc);
bench_clients(N, Acc, Fun) ->
    with_client(fun(Test, Client, Parent, Handle) ->
        bench_clients(N - 1, [{warden@resource:new(Client, <<"https://api.test">>),
                              token(Test), cache(Parent), Handle} | Acc], Fun)
    end).
bench(Clients) ->
    lists:foreach(fun({V, T, _, _}) -> [warden@resource:verify(V, T) || _ <- lists:seq(1, 100)] end, Clients),
    Parent = self(),
    Start = erlang:monotonic_time(microsecond),
    [spawn(fun() ->
        Times = [begin S = erlang:monotonic_time(microsecond),
                       {ok, _} = warden@resource:verify(V, T),
                       erlang:monotonic_time(microsecond) - S end || _ <- lists:seq(1, 3000)],
        Parent ! {sample, Times}
    end) || {V, T, _, _} <- Clients],
    Samples = lists:append([receive {sample, S} -> S after 30000 -> error(bench_timeout) end || _ <- Clients]),
    Elapsed = erlang:monotonic_time(microsecond) - Start,
    Sorted = lists:sort(Samples),
    io:format("clients=~p validations=~p total_us=~p throughput_per_s=~p p50_us=~p p95_us=~p p99_us=~p cache_info=~p~n",
        [length(Clients), length(Samples), Elapsed, length(Samples) * 1000000 div Elapsed,
         lists:nth(length(Sorted) div 2, Sorted), lists:nth(length(Sorted) * 95 div 100, Sorted),
         lists:nth(length(Sorted) * 99 div 100, Sorted),
         [process_info(Pid, [monitors, monitored_by, message_queue_len, memory]) || {_, _, Pid, _} <- Clients]]),
    SnapshotStart = erlang:monotonic_time(microsecond),
    [begin {ok, _} = warden@internal@native@provider:snapshot_of(Handle) end
     || _ <- lists:seq(1, 10000), {_, _, _, Handle} <- Clients],
    io:format("snapshot_clients=~p reads=~p total_us=~p~n", [length(Clients), 10000 * length(Clients),
        erlang:monotonic_time(microsecond) - SnapshotStart]).

bookkeeping() ->
    with_client(fun(_, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"measurement">>),
            Worker = blocked(),
            Cache = cache(Parent),
            io:format("active_cache=~w active_worker=~w~n",
                [process_info(Cache, [monitors, monitored_by, links]), process_info(Worker, [monitors, monitored_by, links])]),
            Worker ! release,
            {ok, _} = result(Caller),
            down(Worker, 1000)
        end),
        Start = erlang:monotonic_time(microsecond),
        [begin {ok, _} = warden@internal@native@provider:refresh_keys(Handle, {some, integer_to_binary(N)}) end
         || N <- lists:seq(1, 100)],
        io:format("refresh_count=100 total_us=~p after_burst_cache=~w~n",
            [erlang:monotonic_time(microsecond) - Start,
             process_info(cache(Parent), [monitors, monitored_by, message_queue_len])])
    end).

normal_owner_exit_terminates_owned_worker_test() ->
    Parent = self(),
    Owner = spawn(fun() ->
        Self = gleam@erlang@process:new_subject(),
        Background = warden@internal@native@provider_fetch:start(Self,
            fun() -> Parent ! {owned_worker, self()}, receive finish -> {ok, nil} end end,
            fun(Pid, Result) -> {finished, Pid, Result} end),
        Parent ! {owned_background, Background},
        receive finish -> ok end
    end),
    try receive {owned_background, {background, Guardian, _}} ->
        Worker = receive {owned_worker, Pid} -> Pid after 1000 -> error(no_worker) end,
        WorkerRef = monitor(process, Worker),
        OwnerRef = monitor(process, Owner),
        Owner ! finish,
        receive {'DOWN', OwnerRef, process, Owner, normal} -> ok
        after 1000 -> error(owner_not_normal) end,
        receive {'DOWN', WorkerRef, process, Worker, killed} -> ok
        after 500 -> error(ownerless_worker) end,
        down(Guardian, 1000)
    after 1000 -> error(no_background) end
    after exit(Owner, kill) end.

normal_worker_exit_without_result_is_observed_test() ->
    Self = gleam@erlang@process:new_subject(),
    Parent = self(),
    {background, Guardian, Ref} = warden@internal@native@provider_fetch:start(Self,
        fun() -> Parent ! {normal_worker, self()},
                 receive finish -> exit(self(), normal), {ok, nil} end end,
        fun(Pid, Result) -> {finished, Pid, Result} end),
    try
    Worker = receive {normal_worker, Pid} -> Pid after 1000 -> error(no_worker) end,
    WorkerRef = monitor(process, Worker),
    Worker ! finish,
    receive {'DOWN', WorkerRef, process, Worker, normal} -> ok
    after 1000 -> error(worker_not_normal) end,
    receive {'DOWN', Ref, process, Guardian, normal} -> ok
    after 500 -> error(guardian_stranded) end
    after exit(Guardian, kill), demonitor(Ref, [flush]) end.

guardian_failure_terminates_worker_and_releases_refresh_test() ->
    with_client(fun(_, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"guardian-loss">>),
            Worker = blocked(),
            {monitors, [{process, Guardian}]} = process_info(cache(Parent), monitors),
            stop(Guardian, kill),
            down(Worker, 500),
            ?assertMatch({ok, _}, result(Caller, 500)),
            ?assertMatch({ok, _}, warden@internal@native@provider:snapshot_of(Handle))
        end)
    end).

stalled_request_terminates_on_cache_or_client_exit_test() ->
    lists:foreach(fun(Mode) -> stalled_request(Mode) end, [cache, client]).

stalled_request(Mode) ->
    Slow = warden_test_server:start("localhost", fun(_) ->
        {raw_then_hold, <<"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n">>}
    end),
    Test = warden_test_provider:start(#{<<"jwks_uri">> => warden_test_server:url(Slow, <<"/keys">>)}),
    Id = make_ref(),
    try
        Config0 = warden@config:resource_server(warden_test_provider:issuer(Test)),
        Config1 = warden@config:with_trust(Config0, {trust_anchors_pem, warden_test_support_ffi:ca_pem()}),
        Config2 = warden@config:with_destinations(Config1, allow_loopback_for_testing),
        Config = warden@config:with_request_timeout(Config2, gleam@time@duration:seconds(5)),
        {ok, Client} = warden:new(Config),
        ok = telemetry:attach(Id, [warden, http, request], fun ?MODULE:observe/4, {network, self(), Id}),
        Builder = gleam@otp@static_supervisor:new(one_for_one),
        {ok, {started, Parent, _}} = gleam@otp@static_supervisor:start(
            gleam@otp@static_supervisor:add(Builder, warden:supervised(Client))),
        unlink(Parent),
        try
            Worker = receive {Id, network_worker, Pid} -> Pid after 5000 -> error(no_network_worker) end,
            SlowRef = maps:get(ref, Slow),
            receive {warden_test_request, SlowRef, _} -> ok after 5000 -> error(no_stalled_request) end,
            WorkerRef = monitor(process, Worker),
            case Mode of cache -> stop(cache(Parent), kill); client -> stop(Parent, shutdown) end,
            receive {'DOWN', WorkerRef, process, Worker, _} -> ok
            after 500 -> error(worker_waited_for_transport_deadline) end
        after stop(Parent, shutdown) end
    after
        telemetry:detach(Id),
        warden_test_provider:stop(Test),
        warden_test_server:stop(Slow)
    end.

obsolete_completion_cannot_settle_new_refresh_test() ->
    with_client(fun(Test, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            First = refresh(Handle, <<"first">>),
            Worker = blocked(),
            Cache = cache(Parent),
            {monitors, [{process, Guardian}]} = process_info(Cache, monitors),
            erlang:trace(Guardian, true, [send]),
            Worker ! release,
            {ok, FirstSnapshot} = result(First),
            Completion = receive {trace, Guardian, send, Message, Cache} -> Message
                         after 1000 -> error(no_completion) end,
            catch erlang:trace(Guardian, false, [send]),
            warden@testing:rotate_signing_key(Test),
            warden@testing:rotate_signing_key(Test),
            with_barrier(fun(_) ->
                Next = refresh(Handle, <<"second">>),
                NextWorker = blocked(),
                Cache ! Completion,
                %% This call is sent by the same process after the obsolete
                %% message; its response proves the actor processed that message.
                ?assertMatch({ok, _}, warden@internal@native@provider:snapshot_of(Handle)),
                ?assert(is_process_alive(NextWorker)),
                NextWorker ! release,
                {ok, NextSnapshot} = result(Next),
                ?assertNotEqual(FirstSnapshot, NextSnapshot)
            end)
        end)
    end).

reload_worker_loss_keeps_snapshot_and_schedules_next_reload_test() ->
    with_direct_cache(reload, fun(Cache, Handle) ->
        Worker = blocked(),
        stop(Worker, kill),
        ?assertMatch({ok, _}, warden@internal@native@provider:snapshot_of(Handle)),
        Fresh = next_worker(),
        down(Fresh, 5000),
        ?assert(is_process_alive(Cache)),
        ?assertMatch({ok, _}, warden@internal@native@provider:snapshot_of(Handle))
    end).

discovery_worker_loss_retries_under_existing_backoff_test() ->
    with_direct_cache(discovery, fun(Cache, Handle) ->
        Worker = blocked(),
        stop(Worker, kill),
        ?assertEqual({error, not_ready}, warden@internal@native@provider:snapshot_of(Handle)),
        Fresh = next_worker(),
        down(Fresh, 5000),
        await_ready(Handle, erlang:monotonic_time(millisecond) + 1000),
        ?assert(is_process_alive(Cache))
    end).

reload_and_discovery_owner_loss_stop_post_response_worker_test() ->
    lists:foreach(fun(Mode) ->
        with_direct_cache(Mode, fun(Cache, _) ->
            Worker = blocked(),
            WorkerRef = monitor(process, Worker),
            stop(Cache, shutdown),
            receive {'DOWN', WorkerRef, process, Worker, killed} -> ok
            after 500 -> error(fetch_survived_owner) end
        end)
    end, [reload, discovery]).

with_direct_cache(Mode, Fun) ->
    {ok, Test} = warden@testing:start_provider(warden@testing:provider_options()),
    try
        Seed = case Mode of
            reload -> {some, warden@provider_cache_test:discovered_for_lifecycle(Test)};
            discovery -> none
        end,
        with_barrier(fun(_) ->
            {Cache, Handle} = warden@provider_cache_test:start_for_lifecycle(Test, Seed),
            unlink(Cache),
            try Fun(Cache, Handle) after stop(Cache, shutdown) end
        end)
    after warden@testing:stop_provider(Test) end.

obsolete_down_cannot_release_new_refresh_test() ->
    with_client(fun(Test, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            First = refresh(Handle, <<"first-down">>),
            blocked(),
            Cache = cache(Parent),
            {monitors, [{process, Guardian}]} = process_info(Cache, monitors),
            erlang:trace(Cache, true, ['receive']),
            ok = sys:suspend(Cache),
            try
                stop(Guardian, kill),
                OldDown = receive
                    {trace, Cache, 'receive', {'DOWN', _, process, Guardian, killed} = Message} -> Message
                after 1000 -> error(no_down) end,
                ok = sys:resume(Cache),
                {ok, FirstSnapshot} = result(First),
                erlang:trace(Cache, false, ['receive']),
                warden@testing:rotate_signing_key(Test),
                warden@testing:rotate_signing_key(Test),
                with_barrier(fun(_) ->
                    Next = refresh(Handle, <<"next-down">>),
                    Worker = blocked(),
                    Cache ! OldDown,
                    ?assertMatch({ok, _}, warden@internal@native@provider:snapshot_of(Handle)),
                    Worker ! release,
                    {ok, NextSnapshot} = result(Next),
                    ?assertNotEqual(FirstSnapshot, NextSnapshot)
                end)
            after catch sys:resume(Cache), catch erlang:trace(Cache, false, ['receive']) end
        end)
    end).

completed_fetch_bookkeeping_drains_test() ->
    with_client(fun(_, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"burst-start">>),
            Worker = blocked(),
            Cache = cache(Parent),
            {monitors, [{process, Guardian}]} = process_info(Cache, monitors),
            ?assertEqual([{process, Cache}, {process, Worker}],
                lists:sort(element(2, process_info(Guardian, monitors)))),
            Worker ! release,
            ?assertMatch({ok, _}, result(Caller)),
            down(Worker, 1000),
            down(Guardian, 1000),
            ?assertEqual({monitors, []}, process_info(Cache, monitors))
        end),
        [begin {ok, _} = warden@internal@native@provider:refresh_keys(Handle,
                       {some, integer_to_binary(N)}) end || N <- lists:seq(1, 25)],
        ?assertEqual({monitors, []}, process_info(cache(Parent), monitors)),
        ?assertEqual({message_queue_len, 0}, process_info(cache(Parent), message_queue_len))
    end).

public_stop_terminates_post_response_worker_test() ->
    {ok, Test} = warden@testing:start_provider(warden@testing:provider_options()),
    {ok, Client} = warden:new(warden@testing:config(Test, <<"https://app.test/callback">>)),
    try
        {links, Before} = process_info(self(), links),
        {ok, nil} = warden:start(Client),
        {links, After} = process_info(self(), links),
        [Supervisor] = After -- Before,
        [Cache] = [Pid || {_, Pid, _, _} <- supervisor:which_children(Supervisor),
            {registered_name, Name} <- [process_info(Pid, registered_name)],
            lists:prefix("warden_provider", atom_to_list(Name))],
        {registered_name, Name} = process_info(Cache, registered_name),
        Handle = {provider, {named_subject, Name}, 5000},
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"public-stop">>),
            Worker = blocked(),
            WorkerRef = monitor(process, Worker),
            warden:stop(Client),
            ?assertNot(is_process_alive(Supervisor)),
            receive {'DOWN', WorkerRef, process, Worker, killed} -> ok
            after 500 -> error(public_stop_left_worker) end,
            result(Caller)
        end)
    after warden:stop(Client), warden@testing:stop_provider(Test) end.

snapshot_benchmark() ->
    lists:foreach(fun(N) -> bench_clients(N, [], fun snapshot_samples/1) end, [1, 4]).
snapshot_samples(Clients) ->
    [warden@internal@native@provider:snapshot_of(Handle)
     || _ <- lists:seq(1, 1000), {_, _, _, Handle} <- Clients],
    Start = erlang:monotonic_time(microsecond),
    [begin {ok, _} = warden@internal@native@provider:snapshot_of(Handle) end
     || _ <- lists:seq(1, 20000), {_, _, _, Handle} <- Clients],
    Elapsed = erlang:monotonic_time(microsecond) - Start,
    [erlang:garbage_collect(Pid) || {_, _, Pid, _} <- Clients],
    io:format("snapshot_pair clients=~p reads=~p total_us=~p per_read_us=~p post_gc=~w~n",
        [length(Clients), 20000 * length(Clients), Elapsed, Elapsed / (20000 * length(Clients)),
         [process_info(Pid, [memory, heap_size, total_heap_size, message_queue_len]) || {_, _, Pid, _} <- Clients]]).

queued_completion_after_owner_exit_has_no_named_send_panic_test() ->
    with_client(fun(_, _, Parent, Handle) ->
        with_barrier(fun(_) ->
            Caller = refresh(Handle, <<"queued-completion">>),
            Worker = blocked(),
            {monitors, [{process, Guardian}]} = process_info(cache(Parent), monitors),
            GuardianRef = monitor(process, Guardian),
            WorkerRef = monitor(process, Worker),
            true = erlang:suspend_process(Guardian),
            try
                erlang:trace(Guardian, true, ['receive']),
                Worker ! release,
                %% The worker sends its completion before its exit signal.
                %% The guardian is suspended, so this receive trace proves
                %% that completion is queued before the owner's later DOWN.
                receive {trace, Guardian, 'receive', _} -> ok
                after 1000 -> error(no_queued_completion) end,
                receive {'DOWN', WorkerRef, process, Worker, normal} -> ok
                after 1000 -> error(worker_did_not_finish) end,
                stop(Parent, shutdown),
                true = erlang:resume_process(Guardian),
                receive {'DOWN', GuardianRef, process, Guardian, Reason} -> ?assertEqual(normal, Reason)
                after 1000 -> error(late_completion_guardian_still_alive) end,
                result(Caller)
            after
                catch erlang:resume_process(Guardian),
                exit(Guardian, kill),
                demonitor(GuardianRef, [flush]),
                demonitor(WorkerRef, [flush])
            end
        end)
    end).


whole_tree_restart_waits_for_old_named_child_test() ->
    with_client(fun(Test, Client, Parent, Handle) ->
        with_held_tree_child(Parent, Handle, fun(Tree, Pool) ->
            PoolRef = monitor(process, Pool),
            exit(Tree, kill),
            await_tree_exit(Pool),
            await_child_join(Pool, Parent, erlang:monotonic_time(millisecond) + 2000),
            Pool ! release,
            receive {'DOWN', PoolRef, process, Pool, _} -> ok
            after 2000 -> error(old_pool_still_alive) end,
            await_ready(Handle, erlang:monotonic_time(millisecond) + 5000),
            ?assertMatch({ok, _}, warden@resource:verify(
                warden@resource:new(Client, <<"https://api.test">>), token(Test)))
        end)
    end).

held_previous_child_obeys_startup_deadline_test() ->
    Configure = fun(Config) -> warden@config:with_startup_timeout(
        Config, gleam@time@duration:milliseconds(500)) end,
    with_configured_client(Configure, fun(_, Client, Parent, Handle) ->
        with_held_tree_child(Parent, Handle, fun(Tree, Pool) ->
            exit(Tree, kill),
            await_tree_exit(Pool),
            stop(Parent, kill),
            Started = erlang:monotonic_time(millisecond),
            ?assertEqual({error, startup_timed_out}, warden:start(Client)),
            ?assert(erlang:monotonic_time(millisecond) - Started < 1000),
            ?assert(is_process_alive(Pool)),
            %% All startup monitors are removed on the timeout path.
            ?assertEqual({monitors, []}, process_info(self(), monitors))
        end)
    end).

with_held_tree_child(Parent, Handle, Fun) ->
    [{_, Tree, supervisor, _}] = supervisor:which_children(Parent),
    [{_, Pool, _, _}] = [Child || Child = {0, _, _, _} <- supervisor:which_children(Tree)],
    Id = make_ref(),
    ok = telemetry:attach(Id, [http_gun, lifecycle], fun ?MODULE:hold_tree/4, {self(), Pool, Tree}),
    try
        Caller = refresh(Handle, <<"held-child">>),
        receive {holding_tree_child, Pool} -> ok after 2000 -> error(no_pool_barrier) end,
        Fun(Tree, Pool),
        result(Caller)
    after telemetry:detach(Id), exit(Pool, kill) end.

%% This scheduling barrier keeps the real old HTTP actor's registration
%% alive after it observes its supervisor's exit. It changes no cache state
%% and releases by terminating that same actor, as normal teardown would.
hold_tree(_, _, _, {Parent, Pool, Tree}) when self() =:= Pool ->
    process_flag(trap_exit, true),
    Parent ! {holding_tree_child, Pool},
    receive {'EXIT', Tree, killed} -> Parent ! {tree_exited, Pool}
    after 5000 -> exit(self(), kill) end,
    receive release -> exit(self(), kill) after 5000 -> exit(self(), kill) end;
hold_tree(_, _, _, _) -> ok.

await_tree_exit(Pool) ->
    receive {tree_exited, Pool} -> ok after 2000 -> error(no_tree_exit) end.

await_child_join(Pool, Parent, Deadline) ->
    ?assert(is_process_alive(Parent)),
    {monitored_by, Pids} = process_info(Pool, monitored_by),
    case lists:member(Parent, Pids) of
        true -> ok;
        false ->
            ?assert(erlang:monotonic_time(millisecond) < Deadline),
            erlang:yield(),
            await_child_join(Pool, Parent, Deadline)
    end.
