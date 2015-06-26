PROJECT = oauth2_example

DEPS = lager oauth2_dberl_backend cowboy erlydtl

dep_lager                = git https://github.com/basho/lager.git                2.1.1
dep_oauth2_dberl_backend = git https://github.com/cabol/oauth2_dberl_backend.git master
dep_cowboy               = git https://github.com/extend/cowboy.git              master
dep_erlydtl              = git https://github.com/evanmiller/erlydtl.git         0.10.0

include erlang.mk

ERLC_OPTS += +'{parse_transform, lager_transform}' +debug_info +fail_on_warning
