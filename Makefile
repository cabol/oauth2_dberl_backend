PROJECT = oauth2_dberl_backend

DEPS = dberl oauth2

dep_dberl  = git https://github.com/cabol/dberl.git  master
dep_oauth2 = git https://github.com/kivra/oauth2.git 0.6.0

DIALYZER_DIRS := ebin/
DIALYZER_OPTS := --verbose --statistics -Werror_handling \
                 -Wrace_conditions #-Wunmatched_returns

include erlang.mk
