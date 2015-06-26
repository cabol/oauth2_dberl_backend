%% -------------------------------------------------------------------
%%
%% Copyright (c) 2015 Carlos Andres Bolaños, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%%%-------------------------------------------------------------------
%%% @author Carlos Andres Bolaños R.A. <candres@niagara.io>
%%% @copyright (C) 2015, <Carlos Andres Bolaños>, All Rights Reserved.
%%% @doc dberl backend for kivra oauth2.
%%% @see <a href="https://github.com/kivra/oauth2">OAuth2</a>
%%%-------------------------------------------------------------------
-module(oauth2_dberl_backend).

-behavior(oauth2_backend).

%% API
-export([add_user/2,
         delete_user/1,
         add_client/2,
         add_client/3,
         delete_client/1]).

%% Behavior API
-export([authenticate_user/2,
         authenticate_client/2,
         get_client_identity/2,
         associate_access_code/3,
         associate_refresh_token/3,
         associate_access_token/3,
         resolve_access_code/2,
         resolve_refresh_token/2,
         resolve_access_token/2,
         revoke_access_code/2,
         revoke_access_token/2,
         revoke_refresh_token/2,
         get_redirection_uri/2,
         verify_redirection_uri/3,
         verify_client_scope/3,
         verify_resowner_scope/3,
         verify_scope/3]).

%%%===================================================================
%%% Types and Macros
%%%===================================================================

%% Tables
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).

%% User spec
-opaque user() ::
  #{
    username => binary(),
    password => binary()
  }.

%% Client spec
-opaque client() ::
  #{
    client_id     => binary(),
    client_secret => binary(),
    redirect_uri  => binary()
  }.

-export_type([user/0, client/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec add_user(binary(), binary()) -> ok.
add_user(Username, Password) ->
  put(?USER_TABLE, Username, #{username => Username, password => Password}).

-spec delete_user(binary()) -> ok.
delete_user(Username) ->
  delete(?USER_TABLE, Username).

-spec add_client(binary(), binary(), binary()) -> ok.
add_client(Id, Secret, RedirectUri) ->
  put(?CLIENT_TABLE, Id, #{client_id => Id,
                           client_secret => Secret,
                           redirect_uri => RedirectUri}).

-spec add_client(binary(), binary()) -> ok.
add_client(Id, Secret) ->
  add_client(Id, Secret, undefined).

-spec delete_client(binary()) -> ok.
delete_client(Id) ->
  delete(?CLIENT_TABLE, Id).

%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

%% @hidden
authenticate_user({Username, Password}, _) ->
  case get(?USER_TABLE, Username) of
    {ok, #{<<"password">> := Password}} ->
      {ok, {<<"user">>, Username}};
    {ok, #{<<"password">> := _WrongPassword}} ->
      {error, badpass};
    Error = {error, notfound} ->
      Error
  end.

%% @hidden
authenticate_client({ClientId, ClientSecret}, _) ->
  case get(?CLIENT_TABLE, ClientId) of
    {ok, #{<<"client_secret">> := ClientSecret}} ->
      {ok, {<<"client">>, ClientId}};
    {ok, #{<<"client_secret">> := _WrongSecret}} ->
      {error, badsecret};
    _ ->
      {error, notfound}
  end.

%% @hidden
get_client_identity(ClientId, _) ->
  case get(?CLIENT_TABLE, ClientId) of
    {ok, _} ->
      {ok, {<<"client">>, ClientId}};
    _ ->
      {error, notfound}
  end.

%% @hidden
associate_access_code(AccessCode, GrantCtx, AppCtx) ->
  associate_access_token(AccessCode, GrantCtx, AppCtx).

%% @hidden
associate_access_token(AccessToken, GrantCtx, AppCtx) ->
  put(?ACCESS_TOKEN_TABLE, AccessToken, maps:from_list(GrantCtx)),
  {ok, AppCtx}.

%% @hidden
associate_refresh_token(RefreshToken, GrantCtx, AppCtx) ->
  put(?REFRESH_TOKEN_TABLE, RefreshToken, maps:from_list(GrantCtx)),
  {ok, AppCtx}.

%% @hidden
resolve_access_code(AccessCode, AppCtx) ->
  resolve_access_token(AccessCode, AppCtx).

%% @hidden
resolve_refresh_token(RefreshToken, AppCtx) ->
  resolve_access_token(RefreshToken, AppCtx).

%% @hidden
resolve_access_token(AccessToken, AppCtx) ->
  %% The case trickery is just here to make sure that
  %% we don't propagate errors that cannot be legally
  %% returned from this function according to the spec.
  case get(?ACCESS_TOKEN_TABLE, AccessToken) of
    {ok, Value} ->
      {ok, {AppCtx, maps:to_list(Value)}};
    Error = {error, notfound} ->
      Error
  end.

%% @hidden
revoke_access_code(AccessCode, AppCtx) ->
  revoke_access_token(AccessCode, AppCtx).

%% @hidden
revoke_access_token(AccessToken, AppCtx) ->
  delete(?ACCESS_TOKEN_TABLE, AccessToken),
  {ok, AppCtx}.

%% @hidden
revoke_refresh_token(_RefreshToken, AppCtx) ->
  {ok, AppCtx}.

%% @hidden
get_redirection_uri(ClientId, AppCtx) ->
  case get(?CLIENT_TABLE, ClientId) of
    {ok, #{<<"redirect_uri">> := RedirectUri}} ->
      {ok, {AppCtx, RedirectUri}};
    Error = {error, notfound} ->
      Error
  end.

%% @hidden
verify_redirection_uri(ClientId, ClientUri, AppCtx) ->
  case get(?CLIENT_TABLE, ClientId) of
    {ok, #{<<"redirect_uri">> := RedirUri}} when ClientUri =:= RedirUri ->
      {ok, AppCtx};
    _Error ->
      {error, mismatch}
  end.

%% @hidden
verify_client_scope(_Client, Scope, AppCtx) ->
  {ok, {AppCtx, Scope}}.

%% @hidden
verify_resowner_scope(_ResOwner, Scope, AppCtx) ->
  {ok, {AppCtx, Scope}}.

%% @hidden
verify_scope(Scope, Scope, AppCtx) ->
  {ok, {AppCtx, Scope}};
verify_scope(_, _, _) ->
  {error, invalid_scope}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
get(Table, Key) ->
  case dberl_repo:fetch(Table, Key) of
    {error, notfound} -> {error, notfound};
    Value             -> {ok, Value}
  end.

%% @private
put(Table, Key, Value) ->
  dberl_repo:set(Table, Key, Value).

%% @private
delete(Table, Key) ->
  dberl_repo:delete(Table, Key).
