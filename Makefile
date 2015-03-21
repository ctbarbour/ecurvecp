PROJECT ?= $(notdir $(CURDIR))
PROJECT := $(strip $(PROJECT))
ERL 		= $(shell which erl)

REBAR		?= ./rebar
export REBAR

DIALYZER_PLT  = .$(PROJECT).plt
DIALYZER_OPTS ?= -Werror_handling -Wrace_conditions -Wunmatched_returns
PLT_APPS 		  = erts kernel stdlib sasl

.PHONY: all deps shell xref doc eunit

DEPS = enacl druuid proper
dep_enacl = git https://github.com/jlouis/enacl.git master
dep_druuid = git https://github.com/kellymclaughlin/druuid.git master
dep_proper = git https://github.com/manopapad/proper.git master

all: deps compile

clean:
	@$(REBAR) clean

deps:
	@$(REBAR) get-deps

compile:
	@$(REBAR) compile

xref:
	@$(REBAR) xref skip_deps=true

eunit: compile
	@$(REBAR) eunit skip_deps=true

ct: compile
	@$(REBAR) ct skip_deps=true

doc: compile
	@$(REBAR) skip_deps=true doc

$(DIALYZER_PLT):
	@dialyzer --output_plt $(DIALYZER_PLT) --build_plt \
		--apps $(PLT_APPS) -r deps

dialyze: compile $(DIALYZER_PLT)
	@dialyzer --plt $(DIALYZER_PLT) $(DIALYZER_OPTS) \
		-r ./ebin

shell: all
	@$(ERL) \
		-pa ./ebin -pa ./deps/*/ebin \
		-boot start_sasl \
		-config ./config/sys.config
