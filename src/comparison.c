/*
 * What two resolved plans grant relative to each other, beyond containment:
 * their difference and their overlap. Both read the regions of
 * maelys_plan_walk_regions(), so they are exact for the permissions of the
 * two plans under the conditions of containment.
 */
#include "internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { BEFORE = 0, AFTER = 1 };

typedef struct diff_path {
  char *path;
  maelys_sandbox_policy_permission_t self[2];
  maelys_sandbox_policy_permission_t below[2];
} diff_path_t;

struct maelys_sandbox_policy_diff {
  diff_path_t *paths;
  size_t path_count;
  size_t path_capacity;
  size_t *added;
  size_t added_count;
  size_t *removed;
  size_t removed_count;
  unsigned widens;
  unsigned narrows;
  int failed;
};

static int same_pair(const maelys_sandbox_policy_permission_t a[2],
                     const maelys_sandbox_policy_permission_t b[2]) {
  return a[BEFORE] == b[BEFORE] && a[AFTER] == b[AFTER];
}

/* An entry is kept where the pair of permissions stops being the one of the
 * path above, and something there, or above, did change: a path the two
 * plans treat alike under an unchanged tree says nothing. */
static int collect_difference(const maelys_plan_region_t *region, void *context) {
  maelys_sandbox_policy_diff_t *diff = context;
  const unsigned filesystem = MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM;
  if (region->self[AFTER] > region->self[BEFORE] ||
      region->below[AFTER] > region->below[BEFORE])
    diff->widens |= filesystem;
  if (region->self[AFTER] < region->self[BEFORE] ||
      region->below[AFTER] < region->below[BEFORE])
    diff->narrows |= filesystem;
  int differs_from_above = !same_pair(region->self, region->inherited) ||
                           !same_pair(region->below, region->inherited);
  int changed = region->self[BEFORE] != region->self[AFTER] ||
                region->below[BEFORE] != region->below[AFTER] ||
                region->inherited[BEFORE] != region->inherited[AFTER];
  if (!differs_from_above || !changed)
    return 0;
  if (diff->path_count == diff->path_capacity) {
    size_t next = diff->path_capacity ? diff->path_capacity * 2u : 16u;
    diff_path_t *grown = realloc(diff->paths, next * sizeof(*grown));
    if (!grown) {
      diff->failed = 1;
      return 1;
    }
    diff->paths = grown;
    diff->path_capacity = next;
  }
  diff_path_t entry = {maelys_strdup(region->path),
                       {region->self[BEFORE], region->self[AFTER]},
                       {region->below[BEFORE], region->below[AFTER]}};
  if (!entry.path) {
    diff->failed = 1;
    return 1;
  }
  diff->paths[diff->path_count++] = entry;
  return 0;
}

static const maelys_mir_network_destination_t *
find_destination(const maelys_sandbox_policy_plan_t *plan,
                 const maelys_mir_network_destination_t *wanted, size_t *index) {
  for (size_t i = 0; i < plan->network_destination_count; ++i) {
    const maelys_mir_network_destination_t *d = &plan->network_destinations[i];
    if (d->protocol == wanted->protocol && d->port == wanted->port &&
        strcmp(d->host, wanted->host) == 0) {
      if (index)
        *index = i;
      return d;
    }
  }
  return NULL;
}

/* The destinations of `plan` that `other` does not hold with the same
 * flags. */
static int missing_destinations(const maelys_sandbox_policy_plan_t *plan,
                                const maelys_sandbox_policy_plan_t *other,
                                size_t **out, size_t *out_count) {
  if (!plan->network_destination_count)
    return 1;
  size_t *indexes = malloc(plan->network_destination_count * sizeof(*indexes));
  if (!indexes)
    return 0;
  size_t count = 0;
  for (size_t i = 0; i < plan->network_destination_count; ++i) {
    const maelys_mir_network_destination_t *same =
        find_destination(other, &plan->network_destinations[i], NULL);
    if (!same || same->flags != plan->network_destinations[i].flags)
      indexes[count++] = i;
  }
  *out = indexes;
  *out_count = count;
  return 1;
}

void maelys_sandbox_policy_diff_destroy(maelys_sandbox_policy_diff_t *diff) {
  if (!diff)
    return;
  for (size_t i = 0; i < diff->path_count; ++i)
    free(diff->paths[i].path);
  free(diff->paths);
  free(diff->added);
  free(diff->removed);
  free(diff);
}

maelys_mir_result_t maelys_sandbox_policy_plan_diff(
    const maelys_sandbox_policy_plan_t *before,
    const maelys_sandbox_policy_plan_t *after,
    maelys_sandbox_policy_diff_t **out, char **err) {
  if (out)
    *out = NULL;
  if (!before || !after || !out) {
    maelys_set_error(err, "two plans and the diff output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_sandbox_policy_diff_t *diff = calloc(1, sizeof(*diff));
  if (!diff)
    return MAELYS_MIR_ERR_MEMORY;
  maelys_mir_result_t result = maelys_plan_walk_regions(
      before->rules, before->rule_count, after->rules, after->rule_count,
      collect_difference, diff);
  if (result == MAELYS_MIR_OK &&
      (diff->failed ||
       !missing_destinations(after, before, &diff->added, &diff->added_count) ||
       !missing_destinations(before, after, &diff->removed,
                             &diff->removed_count)))
    result = MAELYS_MIR_ERR_MEMORY;
  if (result != MAELYS_MIR_OK) {
    maelys_sandbox_policy_diff_destroy(diff);
    return result;
  }
  size_t ignored;
  if (maelys_plan_network_excess(before, after, &ignored))
    diff->widens |= MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK;
  if (maelys_plan_network_excess(after, before, &ignored))
    diff->narrows |= MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK;
  if (before->root_mode != after->root_mode) {
    if (after->root_mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE)
      diff->widens |= MAELYS_SANDBOX_POLICY_DIMENSION_ROOT;
    else
      diff->narrows |= MAELYS_SANDBOX_POLICY_DIMENSION_ROOT;
  }
  if (before->process_tree_required != after->process_tree_required) {
    if (before->process_tree_required)
      diff->widens |= MAELYS_SANDBOX_POLICY_DIMENSION_PROCESS;
    else
      diff->narrows |= MAELYS_SANDBOX_POLICY_DIMENSION_PROCESS;
  }
  *out = diff;
  return MAELYS_MIR_OK;
}

unsigned maelys_sandbox_policy_diff_widens(const maelys_sandbox_policy_diff_t *d) {
  return d ? d->widens : 0u;
}
unsigned maelys_sandbox_policy_diff_narrows(const maelys_sandbox_policy_diff_t *d) {
  return d ? d->narrows : 0u;
}
size_t maelys_sandbox_policy_diff_path_count(const maelys_sandbox_policy_diff_t *d) {
  return d ? d->path_count : 0u;
}
maelys_mir_result_t maelys_sandbox_policy_diff_path_at(
    const maelys_sandbox_policy_diff_t *d, size_t i,
    maelys_sandbox_policy_diff_path_view_t *out) {
  if (!d || !out || i >= d->path_count)
    return MAELYS_MIR_ERR_ARGUMENT;
  *out = (maelys_sandbox_policy_diff_path_view_t){
      d->paths[i].path, d->paths[i].self[BEFORE], d->paths[i].self[AFTER],
      d->paths[i].below[BEFORE], d->paths[i].below[AFTER]};
  return MAELYS_MIR_OK;
}
size_t maelys_sandbox_policy_diff_added_destination_count(
    const maelys_sandbox_policy_diff_t *d) {
  return d ? d->added_count : 0u;
}
size_t maelys_sandbox_policy_diff_added_destination_at(
    const maelys_sandbox_policy_diff_t *d, size_t i) {
  return d && i < d->added_count ? d->added[i] : SIZE_MAX;
}
size_t maelys_sandbox_policy_diff_removed_destination_count(
    const maelys_sandbox_policy_diff_t *d) {
  return d ? d->removed_count : 0u;
}
size_t maelys_sandbox_policy_diff_removed_destination_at(
    const maelys_sandbox_policy_diff_t *d, size_t i) {
  return d && i < d->removed_count ? d->removed[i] : SIZE_MAX;
}

/* ---- overlap ---------------------------------------------------------------- */

typedef struct overlap_search {
  const char *base[2]; /* a region both read, a region both write */
  int below[2];
} overlap_search_t;

static maelys_sandbox_policy_permission_t
common(const maelys_sandbox_policy_permission_t granted[2]) {
  return granted[0] < granted[1] ? granted[0] : granted[1];
}

static int first_overlap(const maelys_plan_region_t *region, void *context) {
  overlap_search_t *search = context;
  static const maelys_sandbox_policy_permission_t wanted[2] = {
      MAELYS_SANDBOX_POLICY_PERMISSION_READ,
      MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE};
  for (unsigned level = 0; level < 2u; ++level) {
    if (search->base[level])
      continue;
    if (common(region->self) >= wanted[level]) {
      search->base[level] = region->path;
    } else if (common(region->below) >= wanted[level]) {
      search->base[level] = region->path;
      search->below[level] = 1;
    }
  }
  return search->base[0] && search->base[1];
}

void maelys_sandbox_policy_overlap_clear(maelys_sandbox_policy_overlap_t *overlap) {
  if (!overlap)
    return;
  free(overlap->read_path);
  free(overlap->write_path);
  memset(overlap, 0, sizeof(*overlap));
  overlap->first_destination = overlap->second_destination = SIZE_MAX;
}

maelys_mir_result_t maelys_sandbox_policy_plan_overlaps(
    const maelys_sandbox_policy_plan_t *first,
    const maelys_sandbox_policy_plan_t *second,
    maelys_sandbox_policy_overlap_t *out, char **err) {
  if (out) {
    out->read_path = out->write_path = NULL;
    maelys_sandbox_policy_overlap_clear(out);
  }
  if (!first || !second || !out) {
    maelys_set_error(err, "two plans and the overlap output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  overlap_search_t search = {{NULL, NULL}, {0, 0}};
  maelys_mir_result_t result = maelys_plan_walk_regions(
      first->rules, first->rule_count, second->rules, second->rule_count,
      first_overlap, &search);
  if (result != MAELYS_MIR_OK)
    return result;
  char **paths[2] = {&out->read_path, &out->write_path};
  for (unsigned level = 0; level < 2u; ++level) {
    if (!search.base[level])
      continue;
    *paths[level] = maelys_plan_region_witness(
        first->rules, first->rule_count, second->rules, second->rule_count,
        search.base[level], search.below[level]);
    if (!*paths[level]) {
      maelys_sandbox_policy_overlap_clear(out);
      return MAELYS_MIR_ERR_MEMORY;
    }
  }
  if (out->read_path)
    out->dimensions |= MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM;

  int first_direct = first->network == MAELYS_MIR_NETWORK_DIRECT;
  int second_direct = second->network == MAELYS_MIR_NETWORK_DIRECT;
  if (first->network == MAELYS_MIR_NETWORK_NONE ||
      second->network == MAELYS_MIR_NETWORK_NONE)
    return MAELYS_MIR_OK;
  if (first_direct || second_direct) {
    /* A direct network reaches every destination the other names. */
    out->dimensions |= MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK;
    if (!first_direct)
      out->first_destination = 0u;
    if (!second_direct)
      out->second_destination = 0u;
    return MAELYS_MIR_OK;
  }
  for (size_t i = 0; i < first->network_destination_count; ++i) {
    size_t j = 0;
    if (find_destination(second, &first->network_destinations[i], &j)) {
      out->dimensions |= MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK;
      out->first_destination = i;
      out->second_destination = j;
      break;
    }
  }
  return MAELYS_MIR_OK;
}
