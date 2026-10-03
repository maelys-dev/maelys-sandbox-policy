/*
 * The network destination contract against its corpus: a reference
 * evaluator written from docs/destination-contract.md, the format of the
 * cases, and the claim that the builder refuses every wildcard until the
 * format carries the form.
 */
#include "maelys/mir.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define FAIL_CASE(...)                                                         \
  do {                                                                         \
    fprintf(stderr, "FAIL %s:%zu: ", file, line_number);                       \
    fprintf(stderr, __VA_ARGS__);                                              \
    fputc('\n', stderr);                                                       \
    ++failures;                                                                \
  } while (0)

#define MAX_DESTINATIONS 8u
#define MAX_REQUESTS 16u
#define NAME_BYTES 256u

typedef struct destination {
  char name[NAME_BYTES];
  unsigned port;
  int require_sni;
  int allow_private;
} destination_t;

typedef enum reason {
  ALLOWED = 0,
  NETWORK_NONE,
  MALFORMED_NAME,
  NO_DESTINATION,
  SNI_ABSENT,
  SNI_MISMATCH,
  PRIVATE_ADDRESS
} reason_t;

static const char *const reason_names[] = {
    "allowed",    "network-none", "malformed-name",  "no-destination",
    "sni-absent", "sni-mismatch", "private-address",
};

typedef struct request {
  char name[NAME_BYTES];
  unsigned port;
  char sni[NAME_BYTES]; /* empty: absent */
  int is_private;
  reason_t verdict;
} request_t;

/* A label a resolver may read as a number, judged before the case is
 * lowered; and the strict dotted IPv4 the contract accepts instead. */
static int numeric_label(const char *label, size_t n) {
  if (n > 2u && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')) {
    for (size_t i = 2; i < n; ++i)
      if (!strchr("0123456789abcdefABCDEF", label[i]))
        return 0;
    return 1;
  }
  for (size_t i = 0; i < n; ++i)
    if (label[i] < '0' || label[i] > '9')
      return 0;
  return n > 0;
}

static int strict_ipv4(const char *name) {
  int octets = 0;
  for (const char *p = name;; ++p) {
    size_t n = 0;
    unsigned value = 0;
    for (; p[n] >= '0' && p[n] <= '9'; ++n)
      value = value * 10u + (unsigned)(p[n] - '0');
    if (n == 0 || n > 3u || (n > 1u && p[0] == '0') || value > 255u)
      return 0;
    ++octets;
    p += n;
    if (*p == '\0')
      return octets == 4;
    if (*p != '.' || octets == 4)
      return 0;
  }
}

/* A canonical name as the contract defines it: the mediators agree on this
 * grammar, and the builder has the same one. */
static int canonical_name(const char *name) {
  size_t length = strlen(name), label = 0;
  if (length == 0 || length > 253u)
    return 0;
  for (size_t i = 0; i < length; ++i) {
    char c = name[i];
    if (c == '.') {
      if (label == 0 || name[i - 1u] == '-')
        return 0;
      label = 0;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
      return 0;
    if (label == 0 && c == '-')
      return 0;
    if (++label > 63u)
      return 0;
  }
  if (!(label > 0 && name[length - 1u] != '-'))
    return 0;
  if (numeric_label(name + length - label, label))
    return strict_ipv4(name);
  return 1;
}

/* Anything with a star is meant as a wildcard; only `*.suffix` is one. */
/* A port as the corpus writes it: decimal digits only, 1 to 65535. */
static int parse_port(const char *text, unsigned *out) {
  unsigned value = 0;
  if (*text == '\0' || strlen(text) > 5u)
    return 0;
  for (; *text; ++text) {
    if (*text < '0' || *text > '9')
      return 0;
    value = value * 10u + (unsigned)(*text - '0');
  }
  if (value == 0 || value > 65535u)
    return 0;
  *out = value;
  return 1;
}

static int is_wildcard(const char *name) { return strchr(name, '*') != NULL; }

/* `*.suffix`, suffix canonical with at least two labels, the last one not
 * numeric, so that no literal lies under a wildcard. */
static int well_formed_wildcard(const char *name) {
  if (strlen(name) > 253u || strncmp(name, "*.", 2u) != 0 ||
      !canonical_name(name + 2))
    return 0;
  const char *last = strrchr(name + 2, '.');
  return last != NULL && !numeric_label(last + 1, strlen(last + 1));
}

static int matches(const destination_t *d, const request_t *r) {
  if (d->port != r->port)
    return 0;
  if (!is_wildcard(d->name))
    return strcmp(d->name, r->name) == 0;
  size_t suffix = strlen(d->name + 1), name = strlen(r->name);
  return name > suffix &&
         strcmp(r->name + (name - suffix), d->name + 1) == 0;
}

static reason_t judge(const destination_t *d, const request_t *r) {
  if (d->require_sni) {
    if (r->sni[0] == '\0')
      return SNI_ABSENT;
    if (strcmp(r->sni, r->name) != 0)
      return SNI_MISMATCH;
  }
  if (r->is_private && !d->allow_private)
    return PRIVATE_ADDRESS;
  return ALLOWED;
}

static reason_t evaluate(maelys_mir_network_mode_t mode,
                         const destination_t *destinations, size_t count,
                         const request_t *r) {
  if (mode == MAELYS_MIR_NETWORK_NONE)
    return NETWORK_NONE;
  if (mode == MAELYS_MIR_NETWORK_DIRECT)
    return ALLOWED;
  if (!canonical_name(r->name))
    return MALFORMED_NAME;
  reason_t worst = NO_DESTINATION;
  for (size_t i = 0; i < count; ++i) {
    if (!matches(&destinations[i], r))
      continue;
    reason_t reason = judge(&destinations[i], r);
    if (reason == ALLOWED)
      return ALLOWED;
    if (worst == NO_DESTINATION || reason < worst)
      worst = reason;
  }
  return worst;
}

static int parse_reason(const char *text, reason_t *out) {
  for (size_t i = 0; i < sizeof(reason_names) / sizeof(*reason_names); ++i)
    if (strcmp(text, reason_names[i]) == 0) {
      *out = (reason_t)i;
      return 1;
    }
  return 0;
}

/* The builder refuses every wildcard today, and every literal in disguise
 * for good; the corpus says the former with `requires`, and the format
 * change is what turns those cases on. */
static void check_builder(const char *file, size_t line_number,
                          maelys_mir_network_mode_t mode,
                          const destination_t *destinations, size_t count,
                          int refused_at_source, int accepted) {
  maelys_mir_builder_t *b = NULL;
  char *e = NULL;
  if (maelys_mir_builder_create(&b, &e) != MAELYS_MIR_OK) {
    FAIL_CASE("builder: %s", e ? e : "no diagnostic");
    maelys_mir_error_free(e);
    return;
  }
  maelys_mir_result_t r = maelys_mir_builder_set_network(b, mode, &e);
  for (size_t i = 0; r == MAELYS_MIR_OK && i < count; ++i) {
    maelys_mir_network_destination_flags_t flags = 0;
    if (destinations[i].require_sni)
      flags |= MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI;
    if (destinations[i].allow_private)
      flags |= MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES;
    r = maelys_mir_builder_add_network_destination_ex(
        b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, destinations[i].name,
        (uint16_t)destinations[i].port, flags, &e);
  }
  if (refused_at_source && r == MAELYS_MIR_OK)
    FAIL_CASE("the builder accepted a destination the contract refuses");
  if (!refused_at_source && r != MAELYS_MIR_OK)
    FAIL_CASE("the builder refused an exact destination: %s",
              e ? e : "no diagnostic");
  if (!refused_at_source && !accepted)
    FAIL_CASE("compile refused with nothing to refuse");
  maelys_mir_error_free(e);
  maelys_mir_builder_destroy(b);
}

static void run_case(const char *file) {
  FILE *f = fopen(file, "r");
  if (!f) {
    fprintf(stderr, "FAIL %s: cannot open\n", file);
    ++failures;
    return;
  }
  destination_t destinations[MAX_DESTINATIONS];
  request_t requests[MAX_REQUESTS];
  size_t destination_count = 0, request_count = 0, line_number = 0;
  maelys_mir_network_mode_t mode = MAELYS_MIR_NETWORK_MEDIATED;
  int seen_network = 0, requires_wildcard = 0, seen_compile = 0, accepted = 0;
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    ++line_number;
    line[strcspn(line, "\n")] = '\0';
    if (line[0] == '#' || line[0] == '\0')
      continue;
    char a[NAME_BYTES], c[NAME_BYTES];
    unsigned port;
    int consumed = 0;
    if (sscanf(line, "network %255s%n", a, &consumed) == 1 &&
        line[consumed] == '\0') {
      if (seen_network++ || destination_count || request_count)
        FAIL_CASE("network must come once, first");
      if (strcmp(a, "none") == 0)
        mode = MAELYS_MIR_NETWORK_NONE;
      else if (strcmp(a, "direct") == 0)
        mode = MAELYS_MIR_NETWORK_DIRECT;
      else if (strcmp(a, "mediated") != 0)
        FAIL_CASE("unknown network mode %s", a);
    } else if (sscanf(line, "destination tcp %255s %255s%n", a, c,
                      &consumed) == 2) {
      if (!parse_port(c, &port)) {
        FAIL_CASE("port must be 1 to 65535: %s", c);
        continue;
      }
      if (mode != MAELYS_MIR_NETWORK_MEDIATED)
        FAIL_CASE("a destination outside mediated mode");
      if (destination_count == MAX_DESTINATIONS) {
        FAIL_CASE("too many destinations");
        continue;
      }
      destination_t *dest = &destinations[destination_count++];
      memset(dest, 0, sizeof(*dest));
      strcpy(dest->name, a);
      dest->port = port;
      const char *rest = line + consumed;
      while (sscanf(rest, " %255s%n", c, &consumed) == 1) {
        rest += consumed;
        if (strcmp(c, "require-tls-sni") == 0)
          dest->require_sni = 1;
        else if (strcmp(c, "allow-private-addresses") == 0)
          dest->allow_private = 1;
        else
          FAIL_CASE("unknown destination flag %s", c);
      }
      for (size_t i = 0; i + 1 < destination_count; ++i)
        if (strcmp(destinations[i].name, a) == 0 && destinations[i].port == port)
          FAIL_CASE("destination named twice: %s %u", a, port);
    } else if (sscanf(line, "requires %255s%n", a, &consumed) == 1 &&
               line[consumed] == '\0') {
      if (strcmp(a, "network-host-wildcard") != 0)
        FAIL_CASE("unknown capability %s", a);
      requires_wildcard = 1;
    } else if (strncmp(line, "request ", 8u) == 0) {
      if (request_count == MAX_REQUESTS) {
        FAIL_CASE("too many requests");
        continue;
      }
      /* request tcp NAME PORT sni=NAME|absent [private] allowed|refused REASON */
      char copy[sizeof(line)];
      strcpy(copy, line);
      char *words[8];
      size_t n = 0;
      for (char *w = strtok(copy, " "); w; w = strtok(NULL, " ")) {
        if (n == 8u) {
          FAIL_CASE("request line has too many words");
          n = 0;
          break;
        }
        words[n++] = w;
      }
      request_t *req = &requests[request_count++];
      memset(req, 0, sizeof(*req));
      size_t k = 1;
      if (n < 5u || strcmp(words[k++], "tcp") != 0 ||
          strlen(words[k]) >= NAME_BYTES ||
          !parse_port(words[k + 1], &port) ||
          strncmp(words[k + 2], "sni=", 4u) != 0 ||
          strlen(words[k + 2] + 4) >= NAME_BYTES) {
        FAIL_CASE("malformed request line");
        continue;
      }
      strcpy(req->name, words[k]);
      req->port = port;
      if (strcmp(words[k + 2] + 4, "absent") != 0)
        strcpy(req->sni, words[k + 2] + 4);
      k += 3;
      if (k < n && strcmp(words[k], "private") == 0) {
        req->is_private = 1;
        ++k;
      }
      if (k < n && strcmp(words[k], "allowed") == 0) {
        req->verdict = ALLOWED;
        if (k + 1 != n)
          FAIL_CASE("allowed carries no reason");
      } else if (k + 1 < n && strcmp(words[k], "refused") == 0 && k + 2 == n) {
        if (!parse_reason(words[k + 1], &req->verdict) ||
            req->verdict == ALLOWED)
          FAIL_CASE("refused needs a reason of the contract");
      } else {
        FAIL_CASE("verdict must be allowed, or refused with a reason");
      }
      if (req->sni[0] && !canonical_name(req->sni))
        FAIL_CASE("server name is not canonical: %s", req->sni);
    } else if (sscanf(line, "compile %255s%n", a, &consumed) == 1 &&
               line[consumed] == '\0') {
      seen_compile = 1;
      if (strcmp(a, "accepted") == 0)
        accepted = 1;
      else if (strcmp(a, "refused") != 0)
        FAIL_CASE("compile must be accepted or refused");
    } else {
      FAIL_CASE("unknown directive: %s", line);
    }
  }
  fclose(f);
  line_number = 0;

  int has_wildcard = 0, well_formed = 1, disguised = 0;
  for (size_t i = 0; i < destination_count; ++i) {
    if (!is_wildcard(destinations[i].name)) {
      if (!canonical_name(destinations[i].name) ||
          (destinations[i].require_sni && strict_ipv4(destinations[i].name))) {
        well_formed = 0;
        disguised = 1;
      }
      continue;
    }
    has_wildcard = 1;
    if (!well_formed_wildcard(destinations[i].name) ||
        destinations[i].allow_private)
      well_formed = 0;
  }
  if (!seen_compile)
    FAIL_CASE("no compile line");
  if (has_wildcard != requires_wildcard)
    FAIL_CASE("requires network-host-wildcard exactly when a wildcard exists");
  if (accepted != well_formed)
    FAIL_CASE("compile %s, but the contract %s this policy",
              accepted ? "accepted" : "refused",
              well_formed ? "accepts" : "refuses");
  if (!accepted && request_count)
    FAIL_CASE("a refused case has no request line");
  if (accepted && !request_count)
    FAIL_CASE("an accepted case has at least one request");
  for (size_t i = 0; i < request_count; ++i) {
    reason_t got = evaluate(mode, destinations, destination_count, &requests[i]);
    if (got != requests[i].verdict)
      FAIL_CASE("request %s %u: expected %s, contract gives %s",
                requests[i].name, requests[i].port,
                reason_names[requests[i].verdict], reason_names[got]);
  }
  /* The verdict holds for every order: reversed is enough to catch a
   * first-match reading. */
  for (size_t i = 0; i < destination_count / 2u; ++i) {
    destination_t t = destinations[i];
    destinations[i] = destinations[destination_count - 1u - i];
    destinations[destination_count - 1u - i] = t;
  }
  for (size_t i = 0; i < request_count; ++i)
    if (evaluate(mode, destinations, destination_count, &requests[i]) !=
        requests[i].verdict)
      FAIL_CASE("request %s %u depends on destination order",
                requests[i].name, requests[i].port);
  check_builder(file, line_number, mode, destinations, destination_count,
                has_wildcard || disguised, accepted);
}

static int by_name(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: test_destinations CORPUS_CASES_DIRECTORY\n");
    return 2;
  }
  DIR *dir = opendir(argv[1]);
  if (!dir) {
    fprintf(stderr, "cannot open %s\n", argv[1]);
    return 2;
  }
  char *files[256];
  size_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    size_t n = strlen(entry->d_name);
    if (n < 6u || strcmp(entry->d_name + n - 5u, ".case") != 0)
      continue;
    if (count == sizeof(files) / sizeof(*files))
      break;
    size_t size = strlen(argv[1]) + 1u + n + 1u;
    files[count] = malloc(size);
    if (!files[count])
      return 2;
    snprintf(files[count], size, "%s/%s", argv[1], entry->d_name);
    ++count;
  }
  closedir(dir);
  qsort(files, count, sizeof(*files), by_name);
  for (size_t i = 0; i < count; ++i) {
    run_case(files[i]);
    free(files[i]);
  }
  if (count == 0) {
    fprintf(stderr, "no case in %s\n", argv[1]);
    ++failures;
  }
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf("destinations: %zu cases\n", count);
  return 0;
}
