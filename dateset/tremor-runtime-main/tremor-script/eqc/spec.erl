%% Copyright 2020, The Tremor Team
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(spec).

-include_lib("pbt.hrl").

-export([gen/1, gen_array/1, gen_bool/1, gen_float/1,
	 gen_int/1, gen_record/1, gen_string/1, id/0]).

-define(SHRINKEXPR(OpGen, Gen1),
        ?LET([Op, V1], [OpGen, Gen1],
             ?SHRINK({Op, V1}, [V1] ++ model_eval({Op, V1})))).
-define(SHRINKEXPR(OpGen, Gen1, Gen2),
        ?LET([Op, V1, V2], [OpGen, Gen1, Gen2],
             ?SHRINK({Op, V1, V2}, [V1, V2] ++ model_eval({Op, V1, V2})))).
-define(SHRINKEXPR(OpGen, Gen1, Gen2, Gen3),
        ?LET([Op, V1, V2, V3], [OpGen, Gen1, Gen2, Gen3],
             ?SHRINK({Op, V1, V2, V3}, [V1, V2, V3]))).

id() ->
    ?LET(Path,
	 (?SUCHTHAT(Id,
		    (?LET(Id, (list(choose($a, $e))),
			  (list_to_binary(Id)))),
		    (byte_size(Id) > 0))),
	 Path).

float() -> real().

gen(#state{} = S) -> ?SIZED(N, (gen(S, N div 6))).

gen(#state{} = S, N) ->
    frequency([{10, {emit, spec_inner(S, N)}}, {1, drop},
	       {80, spec_inner(S, N)}]).

gen_int(#state{} = S) ->
    ?LET(Expr, ?SIZED(N, (spec_inner_int(S, N div 4))),
         ?SHRINK(Expr, [model_eval(Expr)])).

gen_float(#state{} = S) ->
    ?SIZED(N, (spec_inner_float(S, N div 4))).

gen_string(#state{} = S) ->
    ?SIZED(N, (spec_inner_string(S, N div 4))).

gen_bool(#state{} = S) ->
    ?SIZED(N, (spec_inner_bool(S, N div 4))).

gen_array(#state{} = S) ->
    ?SIZED(N, (spec_inner_array(S, N div 4))).

gen_record(#state{} = S) ->
    ?SIZED(N, (spec_inner_record(S, N div 4))).

spec_inner(#state{} = S, N) ->
    ?LAZY(frequency([{10, spec_inner_float(S, N)},
                     {10, spec_inner_int(S, N)},
                     {10, spec_inner_string(S, N)},
                     {10, spec_inner_bool(S, N)},
                     {10, spec_inner_array(S, N)},
                     {10, spec_inner_record(S, N)}])).

%% FIX ME!! this is simple fix to avoid wrong float comparision in nested structures.
spec_inner_no_float(#state{} = S, N) ->
    ?LAZY((frequency([{10, spec_inner_int(S, N)},
		      {10, spec_inner_string(S, N)},
		      {10, spec_inner_bool(S, N)},
		      {10, spec_inner_array(S, N)},
		      {10, spec_inner_record(S, N)}]))).

spec_inner_int(#state{} = S, N) ->
    ?LAZY(frequency([{10, spec_bop_int(S, N)},
                     {5, spec_uop_int(S, N)},
                     {10, int_or_int_local(S)}])).

spec_inner_float(#state{} = S, N) ->
    ?LAZY(frequency([{10, spec_bop_float(S, N)},
                     {5, spec_uop_float(S, N)},
                     {1, float_or_float_local(S)}])).

spec_inner_string(#state{} = S, N) ->
    ?LAZY(frequency([{5, spec_bop_string(S, N)},
                     {5, spec_string_interpolation(S, N)},
                     {1, string_or_string_local(S)}])).

spec_inner_bool(#state{} = S, N) ->
    ?LAZY(frequency([{10, spec_bop_bool(S, N)},
                     {1, spec_uop_bool(S, N)},
                     {1, bool_or_bool_local(S)}])).

spec_inner_array(S, N) when N =< 1 ->
    array_or_array_local(S);
spec_inner_array(S, N) ->
    {array, list(N - 1, spec_inner_no_float(S, N - 1))}.

literal_record(S, N) when N =< 1 ->
    record_or_record_local(S);
literal_record(S, N) ->
    {record, map(string(), spec_inner_no_float(S, N - 1))}.

spec_inner_record(#state{} = S, N) when N =< 1 ->
    literal_record(S, N);
spec_inner_record(#state{} = S, N) ->
    ?LAZY(frequency([{5, spec_bop_record(S, N - 1)},
                     {10, spec_uop_record(S, N - 1)},
                     {1, literal_record(S, N)}])).

string() ->
    base64:encode(crypto:strong_rand_bytes(rand:uniform(10))).

small_int() -> choose(1, 100).

int_or_int_local(#state{locals = Ls}) ->
    %% io:format("Choosing from ~p\n", [maps:to_list(Ls)]),
    IVs = [{1, {local, K}} || {K, int} <- maps:to_list(Ls)],
    frequency([{3, small_int()} | IVs]).

float_or_float_local(#state{locals = Ls}) ->
    IVs = [{1, {local, K}} || {K, float} <- maps:to_list(Ls)],
    frequency([{3, float()} | IVs]).

bool_or_bool_local(#state{locals = Ls}) ->
    IVs = [{1, {local, K}} || {K, bool} <- maps:to_list(Ls)],
    frequency([{3, bool()} | IVs]).

string_or_string_local(#state{locals = Ls}) ->
    IVs = [{1, {local, K}} || {K, string} <- maps:to_list(Ls)],
    frequency([{3, string()} | IVs]).

array_or_array_local(#state{locals = Ls}) ->
    IVs = [{1, {local, K}}|| {K, array} <- maps:to_list(Ls)],
    frequency([{5, {array, []}} | IVs]).

record_or_record_local(#state{locals = Ls} = S) ->
    IVs = [{1, {local, K}} || {K, record} <- maps:to_list(Ls)],
    frequency([{max(length(IVs), 1),
		{record,
		 map(string(),
		     oneof([bool_or_bool_local(S), int_or_int_local(S),
			    string_or_string_local(S)]))}}
	       | IVs]).

spec_uop_int(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof(['+', '-']), int_or_int_local(S));
spec_uop_int(S, N) ->
    ?SHRINKEXPR(oneof(['+', '-']), spec_inner_int(S, N - 1)).

spec_uop_float(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof(['+', '-']), float_or_float_local(S));
spec_uop_float(S, N) ->
    ?SHRINKEXPR(oneof(['+', '-']), spec_inner_float(S, N - 1)).

% Operations generated by patch_operation
% {merge, Value}
% {merge, Key, Value}
% {insert, Key, Value}
% {upsert, Key, Value}
% {update, Key, Value}
% {erase, Key}
patch_operation(S, N) ->
    frequency([{1,
		{insert, string(), spec_inner_no_float(S, N - 1)}},
	       {1, {upsert, string(), spec_inner_no_float(S, N - 1)}},
	       {1, {update, string(), spec_inner_no_float(S, N - 1)}},
	       {1, {merge, string(), spec_inner_record(S, N - 1)}},
	       {1, {merge, spec_inner_record(S, N - 1)}},
	       {1, {default, string(), spec_inner_record(S, N - 1)}},
	       {1, {default, spec_inner_record(S, N - 1)}},
	       {1, {erase, string()}}]).

% spec_uop_record function returns {patch, generated_record, patch_operations}
spec_uop_record(S, N) when N =< 1 ->
    ?SHRINKEXPR(patch, literal_record(S, N - 1), [patch_operation(S, N - 1)]);
spec_uop_record(S, N) ->
    ?SHRINKEXPR(patch, spec_inner_record(S, N - 1), [patch_operation(S, N - 1)]).

spec_uop_bool(S, N) when N =< 1 ->
    ?SHRINKEXPR('not', bool_or_bool_local(S));
spec_uop_bool(S, N) ->
    ?SHRINKEXPR('not', spec_inner_bool(S, N - 1)).

spec_string_interpolation(_S, N) when N =< 1 ->
    ?SHRINKEXPR('#', string(), string(),
                oneof([float(), string(), small_int()]));
spec_string_interpolation(S, N) ->
    ?SHRINKEXPR('#', string(), string(), spec_inner(S, N - 1)).

spec_bop_string(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof(['+']),
                string_or_string_local(S), string_or_string_local(S));
spec_bop_string(S, N) ->
    N1 = N div 2,
    N2 = N - N1,
    ?SHRINKEXPR(oneof(['+']),
                 spec_bop_string(S, N1), spec_bop_string(S, N2)).

spec_bop_bool(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof(['and', 'or', '==', '!=']),
                bool_or_bool_local(S), bool_or_bool_local(S));
spec_bop_bool(S, N) ->
    N1 = N div 2,
    N2 = N - N1,
    oneof([?SHRINKEXPR(oneof(['and', 'or']),
                        spec_bop_bool(S, N1), spec_bop_bool(S, N2)),
	   ?SHRINKEXPR(oneof(['==', '!=']), spec_inner(S, N1), spec_inner(S, N2)),
	   ?SHRINKEXPR(oneof(['>=', '>', '<', '<=']),
                       oneof([spec_inner_int(S, N1), spec_inner_float(S, N1)]),
                       oneof([spec_inner_int(S, N2), spec_inner_float(S, N2)])),
	   ?SHRINKEXPR(oneof(['>=', '>', '<', '<=']),
                       spec_inner_string(S, N1), spec_inner_string(S, N2))]).

spec_bop_float(S, N) when N =< 1 ->
    oneof([?SHRINKEXPR(oneof(['+', '-', '*', '/']),
                       float_or_float_local(S), float_or_float_local(S)),
	   ?SHRINKEXPR(oneof(['+', '-', '*', '/']),
                       float_or_float_local(S), int_or_int_local(S)),
	   ?SHRINKEXPR(oneof(['+', '-', '*', '/']),
                        int_or_int_local(S), float_or_float_local(S)),
           %% given two integers, only division may result in a float... but need not!
	   ?SHRINKEXPR(oneof(['/']),
                       int_or_int_local(S), int_or_int_local(S))]);
spec_bop_float(S, N) ->
    N1 = N div 2,
    ?SHRINKEXPR(oneof(['+', '-', '*', '/']),
                oneof([spec_inner_int(S, N1), spec_inner_float(S, N1)]),
                oneof([spec_inner_int(S, N1), spec_inner_float(S, N1)])).

spec_bop_int(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof(['+', '-', '*', 'band', 'bxor']),
                 int_or_int_local(S), int_or_int_local(S));
spec_bop_int(S, N) ->
    N1 = N div 2,
    ?SHRINKEXPR(oneof(['+', '-', '*', 'band', 'bxor']),
                 spec_inner_int(S, N1), spec_inner_int(S, N1)).

spec_bop_record(S, N) when N =< 1 ->
    ?SHRINKEXPR(oneof([merge]),
                 literal_record(S, N - 1), literal_record(S, N - 1));
spec_bop_record(S, N) ->
    ?SHRINKEXPR(oneof([merge]),
                 spec_inner_record(S, N - 1), spec_inner_record(S, N - 1)).

%% try evaluating and return either [Value] or [].
model_eval(Expr) ->
    try [model_eval_inner(Expr)]
    catch _:_ ->
            []
    end.

model_eval_inner({Op, V1, V2}) ->
    case apply_op(Op, model_eval_inner(V1), model_eval_inner(V2)) of
        X when is_integer(X), X < 0 ->
            %% [ io:format("overflow ~p ~p ~p = ~p\n", [V1, Op, V2, X]) || X > 16#ffff ],
            {'-', -X};
        Other ->
            Other
    end;
model_eval_inner({Op, V1}) ->
    case {Op, model_eval_inner(V1)} of
        {'-', {'-', X}} -> X;
        {'+', X} -> X;
        X -> X
    end;
model_eval_inner({Op, V1, V2, V3}) ->
    {Op, model_eval_inner(V1), model_eval_inner(V2), model_eval_inner(V3)};
model_eval_inner(X) ->
    X.

apply_op('+', V1, V2) ->
    V1 + V2;
apply_op('-', V1, V2) ->
    V1 - V2;
apply_op('*', V1, V2) ->
    V1 * V2;
apply_op('/', V1, V2) ->
    V1 / V2;
apply_op('band', V1, V2) ->
    V1 band V2;
apply_op('bxor', V1, V2) ->
    V1 bxor V2;
apply_op('>=', V1, V2) ->
    V1 >= V2;
apply_op('>', V1, V2) ->
    V1 > V2;
apply_op('<', V1, V2) ->
    V1 < V2;
apply_op('<=', V1, V2) ->
    V1 =< V2;
apply_op('!=', V1, V2) ->
    V1 =/= V2;
apply_op('==', V1, V2) ->
    V1 == V2.

