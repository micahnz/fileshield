.PHONY: all clean install install-config uninstall test bench lint debug debug-test

CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 \
           -fstack-protector-strong -fstack-clash-protection \
           -Wformat-security -D_FORTIFY_SOURCE=2 -fPIE \
           -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS := -Wl,-z,relro -Wl,-z,now -pie

SRCDIR  := src
OBJDIR  := build
TSTDIR  := tests
BINDIR  := /usr/local/sbin
CLIBINDIR := /usr/local/bin
ETCDIR  := /etc
SYSDDIR := /etc/systemd/system

TARGET  := fileshield
CLITGT  := fileshield-cli

# `make install` never replaces an existing /etc/fileshield.conf (upgrades
# keep local rules). Set REPLACE_CONFIG=1, or run `make install-config`,
# to overwrite it with the shipped defaults.
# With DESTDIR set (packaging), systemctl is skipped entirely.  Otherwise
# the unit is reloaded; restarting a running service is opt-in (RESTART=1)
# because a build that changes mark scope needs the root smoke-test
# protocol in AGENTS.md first.  try-restart keeps a stopped service stopped.
REPLACE_CONFIG ?= 0
RESTART ?= 0

SRCS    := $(SRCDIR)/main.c $(SRCDIR)/utils.c $(SRCDIR)/config.c \
           $(SRCDIR)/cache.c $(SRCDIR)/session.c $(SRCDIR)/notify.c \
           $(SRCDIR)/fanotify.c $(SRCDIR)/inode.c $(SRCDIR)/sha512.c \
           $(SRCDIR)/persist.c $(SRCDIR)/pin.c $(SRCDIR)/reload.c \
           $(SRCDIR)/ruleid.c $(SRCDIR)/prune.c $(SRCDIR)/control.c \
           $(SRCDIR)/control_client.c
OBJS    := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# The CLI's objects are deliberately disjoint from the daemon's: cli.c owns
# the CLI's main() (linking it into fileshield would collide with main.c),
# and cli_ui.c/control_client.c are client-side modules.  All are built by
# the pattern rule; DEPS tracks them so header edits rebuild them too.
CLIOBJS := $(OBJDIR)/cli.o $(OBJDIR)/cli_ui.o $(OBJDIR)/control_client.o \
           $(OBJDIR)/persist.o $(OBJDIR)/pin.o $(OBJDIR)/prune.o \
           $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o
# Test-only twin of cli.o: same source, main renamed to cli_test_main so
# test_cli can fork() one invocation per case.  Never linked into
# fileshield or fileshield-cli.  Derived from CLIOBJS so the two lists
# cannot drift.
CLITESTOBJS := $(patsubst $(OBJDIR)/cli.o,$(OBJDIR)/cli_test.o,$(CLIOBJS))
DEPS    := $(sort $(OBJS:.o=.d) $(CLIOBJS:.o=.d) $(OBJDIR)/cli_test.d)

TESTS   := test_cache test_config test_reload test_utils test_persist test_pin test_session test_sha512 test_inode test_fanotify \
           test_ruleid test_prune test_cli_ui test_control test_cli
TSTBINS := $(TESTS:%=$(OBJDIR)/%)

all: $(OBJDIR)/$(TARGET) $(OBJDIR)/$(CLITGT)

$(OBJDIR)/$(TARGET): $(OBJS)
	@mkdir -p $(OBJDIR)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

# The CLI links only the client-side and file-state modules: cli.c stays
# linkable without the daemon's fanotify/notify/config/cache/session/
# inode/control/reload halves (CLIOBJS is the exhaustive prerequisite set).
$(OBJDIR)/$(CLITGT): $(CLIOBJS)
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(CLIOBJS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# -DFILESHIELD_TEST_CLI renames main -> cli_test_main (and compiles the
# state-file test redirect).  Explicit rule: the pattern rule would look
# for src/cli_test.c, which does not exist.
$(OBJDIR)/cli_test.o: $(SRCDIR)/cli.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -DFILESHIELD_TEST_CLI -c $< -o $@

-include $(DEPS)

$(OBJDIR)/test_cache: $(OBJDIR)/cache.o $(OBJDIR)/utils.o $(TSTDIR)/test_cache.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_cache.c $(OBJDIR)/cache.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_config: $(OBJDIR)/config.o $(OBJDIR)/utils.o $(TSTDIR)/test_config.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_config.c $(OBJDIR)/config.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_utils: $(OBJDIR)/utils.o $(TSTDIR)/test_utils.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_utils.c $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_session: $(OBJDIR)/session.o $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o $(TSTDIR)/test_session.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_session.c $(OBJDIR)/session.o $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_sha512: $(OBJDIR)/sha512.o $(OBJDIR)/utils.o $(TSTDIR)/test_sha512.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_sha512.c $(OBJDIR)/sha512.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_persist: $(OBJDIR)/persist.o $(OBJDIR)/utils.o $(TSTDIR)/test_persist.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_persist.c $(OBJDIR)/persist.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_pin: $(OBJDIR)/pin.o $(OBJDIR)/persist.o $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o $(TSTDIR)/test_pin.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_pin.c $(OBJDIR)/pin.o $(OBJDIR)/persist.o $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_inode: $(OBJDIR)/inode.o $(OBJDIR)/utils.o $(TSTDIR)/test_inode.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_inode.c $(OBJDIR)/inode.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_ruleid: $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o $(TSTDIR)/test_ruleid.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_ruleid.c $(OBJDIR)/ruleid.o $(OBJDIR)/sha512.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_prune: $(OBJDIR)/prune.o $(TSTDIR)/test_prune.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_prune.c $(OBJDIR)/prune.o -o $@

$(OBJDIR)/test_cli_ui: $(OBJDIR)/cli_ui.o $(OBJDIR)/persist.o $(OBJDIR)/utils.o $(TSTDIR)/test_cli_ui.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_cli_ui.c $(OBJDIR)/cli_ui.o $(OBJDIR)/persist.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_control: $(TSTDIR)/test_control.c $(OBJDIR)/control.o $(OBJDIR)/control_client.o \
                        $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o $(OBJDIR)/config.o \
                        $(OBJDIR)/cache.o $(OBJDIR)/session.o $(OBJDIR)/sha512.o \
                        $(OBJDIR)/persist.o $(OBJDIR)/inode.o $(OBJDIR)/pin.o \
                        $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_control.c $(OBJDIR)/control.o \
		$(OBJDIR)/control_client.o $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
		$(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
		$(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
		$(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o \
		$(OBJDIR)/utils.o -o $@

# CLI behaviour suite: links the test twin of cli.c (cli_test.o) instead
# of cli.o so main never collides and the suite can fork() each case.
$(OBJDIR)/test_cli: $(TSTDIR)/test_cli.c $(CLITESTOBJS)
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_cli.c $(CLITESTOBJS) -o $@

# Links the full event pipeline: fanotify.o needs notify/config/cache/
# session/sha512/persist/utils, and the test supplies the daemon's signal
# globals.
$(OBJDIR)/test_fanotify: $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
                         $(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
                         $(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
                         $(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
                         $(OBJDIR)/control.o $(OBJDIR)/control_client.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
		$(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
		$(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
		$(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
		$(OBJDIR)/control.o $(OBJDIR)/control_client.o -o $@

# Links the reload decision path with fan_fd = -1: every kernel mark fails,
# so parse failure, reject plus rollback, and rollback failure are exercised
# without privileges.
$(OBJDIR)/test_reload: $(TSTDIR)/test_reload.c $(OBJDIR)/reload.o $(OBJDIR)/fanotify.o \
                       $(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
                       $(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
                       $(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
                       $(OBJDIR)/control.o $(OBJDIR)/control_client.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/test_reload.c $(OBJDIR)/reload.o $(OBJDIR)/fanotify.o \
		$(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
		$(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
		$(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
		$(OBJDIR)/control.o $(OBJDIR)/control_client.o -o $@

test: all $(TSTBINS)
	@failed=0; skips=0; \
	for t in $(TSTBINS); do \
		echo "=== $$t ==="; \
		out=`$$t 2>&1` || failed=1; \
		printf '%s\n' "$$out"; \
		n=`printf '%s\n' "$$out" | grep -c '^SKIP'`; \
		skips=`expr $$skips + $$n`; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "FAIL"; \
		exit 1; \
	elif [ $$skips -gt 0 ]; then \
		echo "PASS ($$skips environment-skipped test check(s))"; \
	else \
		echo "PASS"; \
	fi

# Hot-path microbenchmarks (not part of `make test`): timing baselines
# for the optimization work live in the commit messages and in comments
# at the changed sites.  Needs the same objects as the daemon.
$(OBJDIR)/bench_hotpath: $(TSTDIR)/bench_hotpath.c $(OBJDIR)/fanotify.o \
                         $(OBJDIR)/notify.o $(OBJDIR)/config.o \
                         $(OBJDIR)/cache.o $(OBJDIR)/session.o \
                         $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
                         $(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
                         $(OBJDIR)/control.o $(OBJDIR)/control_client.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TSTDIR)/bench_hotpath.c $(OBJDIR)/fanotify.o \
		$(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
		$(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
		$(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/ruleid.o $(OBJDIR)/prune.o $(OBJDIR)/utils.o \
		$(OBJDIR)/control.o $(OBJDIR)/control_client.o -o $@

bench: all $(OBJDIR)/bench_hotpath
	./$(OBJDIR)/bench_hotpath

install: all
	install -m 0755 -D $(OBJDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 0755 -D $(OBJDIR)/$(CLITGT) $(DESTDIR)$(CLIBINDIR)/$(CLITGT)
	@if [ "$(REPLACE_CONFIG)" = "1" ]; then \
		install -m 0640 -D fileshield.conf "$(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "installed default config (overwrote $(DESTDIR)$(ETCDIR)/fileshield.conf)"; \
	elif [ -e "$(DESTDIR)$(ETCDIR)/fileshield.conf" ]; then \
		echo "keeping existing $(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "  (set REPLACE_CONFIG=1 to overwrite it with the shipped defaults)"; \
	else \
		install -m 0640 -D fileshield.conf "$(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "installed default config to $(DESTDIR)$(ETCDIR)/fileshield.conf"; \
	fi
	install -m 0644 -D fileshield.service "$(DESTDIR)$(SYSDDIR)/fileshield.service"
	@if [ -z "$(DESTDIR)" ]; then \
		if ! systemctl daemon-reload; then \
			echo "warning: systemctl daemon-reload failed; not restarting fileshield" >&2; \
		elif [ "$(RESTART)" = "1" ]; then \
			if [ "$$(id -u)" -eq 0 ]; then \
				systemctl try-restart fileshield; \
			else \
				sudo systemctl try-restart fileshield; \
			fi; \
		else \
			echo "installed; fileshield was NOT restarted (mark-scope changes need a root smoke test first)"; \
			echo "  restart when ready: sudo systemctl restart fileshield   (or re-run with RESTART=1)"; \
		fi; \
	else \
		echo "staged install ($(DESTDIR)): skipping systemctl"; \
	fi

# Convenience alias for `make install REPLACE_CONFIG=1`.
install-config:
	$(MAKE) install REPLACE_CONFIG=1

# Remove the installed binaries and unit.  Never touches /etc/fileshield.conf
# or the state and pins under /var/lib/fileshield.  Stops and disables the
# unit first so a running daemon does not outlive its binary.
uninstall:
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl disable --now fileshield || true; \
	fi
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(CLIBINDIR)/$(CLITGT)"
	rm -f "$(DESTDIR)$(SYSDDIR)/fileshield.service"
	@if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	@echo "removed $(DESTDIR)$(BINDIR)/$(TARGET), $(DESTDIR)$(CLIBINDIR)/$(CLITGT) and $(DESTDIR)$(SYSDDIR)/fileshield.service"
	@echo "left /etc/fileshield.conf and /var/lib/fileshield untouched"

clean:
	rm -rf $(OBJDIR)

lint:
	cppcheck --std=c99 --enable=all --suppress=missingIncludeSystem \
		--suppress=unusedFunction --suppress=checkersReport \
		--suppress=normalCheckLevelMaxBranches \
		--suppress=unmatchedSuppression \
		--suppress=variableScope --suppress=constVariablePointer \
		--suppress=constParameterCallback \
		--error-exitcode=1 $(SRCDIR)/*.c $(TSTDIR)/*.c

debug: CFLAGS += -O0 -g -U_FORTIFY_SOURCE -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all

# Same sanitizers, but over the whole test suite (the suite link lines use
# LDFLAGS, so ASan/UBSan are active end to end).
debug-test: CFLAGS += -O0 -g -U_FORTIFY_SOURCE -fsanitize=address,undefined
debug-test: LDFLAGS += -fsanitize=address,undefined
debug-test: clean test
