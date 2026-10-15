#!/bin/sh
# Build-time check of the Secure / Non-Secure boundary (run after `make`).
# 1. Secure objects may export ONLY the public API (+ the hw_* layer used inside the secure world).
# 2. Non-secure objects may reference ONLY the public API from the secure world.
# 3. Non-secure sources may not include secure headers (ns_attack.c is the one deliberate exception).
# NOTE: this is build hygiene, not protection. The F103 has no MPU, so a bug or hostile code in the
# non-secure side can still read/write secure RAM by address (see src/ns_attack.c).
NM=${NM:-arm-none-eabi-nm}
API="secure_init secure_tick_1ms secure_authenticate secure_check_permission secure_authorize_entry get_access_status \
get_security_statistics secure_log_next_seq secure_log_read secure_event_name secure_decision_name secure_set_time \
secure_admin_clear_lockout secure_admin_ack_alarm secure_admin_set_servo secure_api_probe"
fail=0
is_api() { for a in $API; do [ "$a" = "$1" ] && return 0; done; return 1; }
is_hw()  { case "$1" in hw_*) return 0;; esac; return 1; }

SEC_DEFS=$($NM -g --defined-only --format=posix build/secure/*.o | awk 'NF>=2 {print $1}' | sort -u)
echo "== secure exports"
for s in $SEC_DEFS; do
  if is_api "$s"; then :; elif is_hw "$s"; then :; elif [ "$s" = "passage_init" ] || [ "$s" = "passage_step" ]; then :; else echo "  LEAK: secure object exports '$s'"; fail=1; fi
done
echo "== non-secure references into secure world"
for o in build/src/*.o; do
  for u in $($NM -u --format=posix "$o" | awk 'NF>=2 {print $1}'); do
    for s in $SEC_DEFS; do
      if [ "$u" = "$s" ] && ! is_api "$s"; then echo "  VIOLATION: $o uses secure-internal symbol '$s'"; fail=1; fi
    done
  done
done
echo "== non-secure includes"
bad=$(grep -lE '#include[[:space:]]+"[^"]*(secure_internal|secure_hw|provisioned_cards|secure_passage)' src/*.c src/*.h 2>/dev/null | grep -v ns_attack.c)
[ -n "$bad" ] && { echo "  VIOLATION: forbidden include in: $bad"; fail=1; }
[ $fail -eq 0 ] && echo "BOUNDARY OK" || echo "BOUNDARY FAILED"
exit $fail
