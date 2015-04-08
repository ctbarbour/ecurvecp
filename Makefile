PROJECT ?= $(notdir $(CURDIR))
PROJECT := $(strip $(PROJECT))
ERL 		= $(shell which erl)

SNAME ?= $(PROJECT)

REBAR		?= ./rebar
export REBAR

DIALYZER_PLT  = .$(PROJECT).plt
DIALYZER_OPTS ?= -Werror_handling -Wrace_conditions -Wunmatched_returns
PLT_APPS 		  = erts kernel stdlib sasl

.PHONY: all deps shell xref doc eunit

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
	ct_run -pa ./ebin -pa ./deps/*/ebin -dir ./test/ -logdir ./test/logs/
	@open ./test/logs/index.html

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
		-sname $(SNAME) \
		-pa ./ebin -pa ./deps/*/ebin -pa ./test \
		-boot start_sasl \
		-config ./config/sys.config
