/*
 * The floor of each public interface, held by the compiler. The current
 * headers come first; the frozen fragments then declare again everything
 * the floor revision declared. A prototype, an enumerator's value, a
 * numeric macro or the layout of an open structure that no longer matches
 * stops this file from compiling: that is a break, and a break raises
 * MAELYS_MIR_ABI_COMPATIBLE_SINCE or MAELYS_SANDBOX_POLICY_ABI_COMPATIBLE_SINCE
 * in the same change that regenerates the fragment with
 * scripts/freeze_abi.py. Additions never touch this file.
 */
#include <maelys/mir.h>
#include <maelys/sandbox_policy.h>

/* First what each floor revision named must still be declared by the
 * headers above; then every declaration is made again and must agree. One
 * fragment per interface, named after the floor it holds. */
#define MAELYS_ABI_FLOOR_PRESENCE
#include "abi-mir-3.h"
#include "abi-sandbox-policy-5.h"
#undef MAELYS_ABI_FLOOR_PRESENCE
#include "abi-mir-3.h"
#include "abi-sandbox-policy-5.h"

#define FLOOR(macro, revision, version, fragment)                              \
  _Static_assert((macro) == (revision), fragment " is the floor " #macro " names"); \
  _Static_assert((macro) <= (version), "a floor cannot be above its revision")
FLOOR(MAELYS_MIR_ABI_COMPATIBLE_SINCE, 3u, MAELYS_MIR_ABI_VERSION,
      "abi-mir-3.h");
FLOOR(MAELYS_SANDBOX_POLICY_ABI_COMPATIBLE_SINCE, 5u,
      MAELYS_SANDBOX_POLICY_ABI_VERSION, "abi-sandbox-policy-5.h");

int abi_floor_holds(void);
int abi_floor_holds(void) { return 1; }
