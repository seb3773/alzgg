/* alz.c — the project's single binary, modelled on ALZipCon: one tool for
 * both ALZip containers, ALZ and EGG.
 *
 *   alzgg list    ARCHIVE
 *   alzgg extract ARCHIVE [-d dest] [-p password]
 *   alzgg create  OUTPUT [-p profile] [...] INPUTS...
 *
 * The format is detected on its own: from the content for `list`/`extract`
 * ('ALZ\x01' or 'EGGA' magic, the extension breaking the tie when the magic
 * cannot be read), from the extension for `create` (.alz → ALZ, .egg → EGG).
 * `--format alz|egg` forces the choice, which is the only way to name an
 * output that has neither extension.
 *
 * Both grammars stay those of the implementations (src/cli_alz.c and
 * src/cli_egg.c): this file only picks which one to call and normalises the
 * position of the output path, so that
 *   alzgg create -o archive.alz …
 *   alzgg create archive.egg …
 *   alzgg create -o archive.egg …
 * all designate the expected format. Options shared by both formats keep the
 * same meaning (-p profile, -v volume size, --password, --crypt-info, -T), and
 * `-s` is refused by ALZ with ALZipCon's message.
 */
#include "alz.h"     /* ALZ_MAGIC */
#include "egg.h"     /* EGG_SIG_ARCHIVE, EGG_SIG_SPLIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int alz_cli_main(int argc, char **argv);
int egg_cli_main(int argc, char **argv);

enum { FMT_NONE = 0, FMT_ALZ = 1, FMT_EGG = 2 };

static void print_header(void)
{
    printf("alzgg (.alz/.egg)\n"
           "(based on ALZip (c) ESTsoft Corp)\n"
           "pure C reimplementation by seb3773\n"
           "https://github.com/seb3773/alzgg\n"
           "\n");
}

static void usage(int rc)
{
    FILE *f = rc ? stderr : stdout;

    fprintf(f,
        "usage:\n"
        "  alzgg list    ARCHIVE [-u|--unix] [-1|--bare]\n"
        "  alzgg extract ARCHIVE [-d dest] [-p password] [-u|--unix] [--raw]\n"
        "  alzgg create  ARCHIVE [-p profile] [-s] [-v size] [-T date[,date...]]\n"
        "                [-mN] [-i id[,id...]] [--password PASS]\n"
        "                [--crypt zip|aes128|aes256|lea128|lea256]\n"
        "                [--crypt-info HEX,...]\n"
        "                INPUTS...\n"
        "\n"
        "Options for list / extract:\n"
        "  -u, --unix    Format paths as Unix relative paths (/ slashes, lowercase)\n"
        "  -1, --bare    Bare output format (one path per line, ideal for scripts, xargs, grep)\n"
        "\n"
        "The format follows the content for list/extract and the extension\n"
        "for create: .alz is an ALZ archive, .egg an EGG archive (volumes\n"
        "included). --format alz|egg forces the choice, on both\n"
        "sub-commands.\n"
        "\n"
        "Profiles (ALZipCon 12.30): ALZ none|faster|normal (-m0...-m2),\n"
        "EGG none|compspeed|normal|compratio|optimized (-m0...-m4). -p is the\n"
        "only password of `extract`, and --password (create) encrypts the\n"
        "archive.\n"
        "Details: FORMAT-ALZ.md and FORMAT-EGG.md.\n");
    exit(rc);
}

static int ext_is(const char *path, const char *ext)
{
    size_t n = strlen(path), m = strlen(ext);

    return n > m && !strcasecmp(path + n - m, ext);
}

static int fmt_from_path(const char *path)
{
    if (ext_is(path, ".alz")) return FMT_ALZ;
    if (ext_is(path, ".egg")) return FMT_EGG;
    return FMT_NONE;
}

/* Read the first four bytes: that is the discriminant ALZip uses, and it
 * depends on neither the file name nor its extension. */
static int fmt_from_magic(const char *path)
{
    unsigned char b[4];
    uint32_t sig;
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f) return FMT_NONE;
    n = fread(b, 1, sizeof b, f);
    fclose(f);
    if (n < sizeof b) return FMT_NONE;
    sig = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
          ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    if (sig == ALZ_MAGIC) return FMT_ALZ;
    if (sig == EGG_SIG_ARCHIVE || sig == EGG_SIG_SPLIT) return FMT_EGG;
    return FMT_NONE;
}

/* Options that consume the next argument: only used to locate the first
 * positional argument (the output, when -o is absent). */
static int takes_value(const char *a)
{
    static const char *const opts[] = {
        "-o", "-p", "-m", "-v", "-T", "-i", "-d", "--attr", "--password",
        "--crypt", "--crypt-info", NULL
    };
    int i;

    for (i = 0; opts[i]; ++i)
        if (!strcmp(a, opts[i])) return 1;
    return 0;
}

static char **dup_args(char *const *argv, int argc)
{
    char **a = calloc((size_t)argc + 1, sizeof *a);
    int i;

    if (!a) {
        fprintf(stderr, "alzgg: out of memory\n");
        exit(2);
    }
    for (i = 0; i < argc; ++i) a[i] = argv[i];
    a[argc] = NULL;
    return a;
}

/* `create`: find the output, deduce the format from it, then present the
 * arguments in the shape the chosen implementation expects. */
static int dispatch_create(int argc, char **argv, int forced)
{
    char **v = dup_args(argv + 2, argc - 2);   /* arguments after "create" */
    char **fwd;
    int n = argc - 2, i, o_i = -1, out_i = -1, fmt = forced, rc;
    const char *out;

    for (i = 0; i < n; ++i) {
        if (!strcmp(v[i], "-o")) { o_i = i; break; }
    }
    for (i = 0; i < n; ++i) {
        if (v[i][0] == '-' && v[i][1]) {
            if (takes_value(v[i]) && i + 1 < n) ++i;
            continue;
        }
        out_i = i;
        break;
    }
    if (o_i >= 0 && o_i + 1 >= n) {
        fprintf(stderr, "alzgg: create: -o expects a path\n");
        free(v);
        return 2;
    }
    out = o_i >= 0 ? v[o_i + 1] : (out_i >= 0 ? v[out_i] : NULL);
    if (!out) {
        fprintf(stderr, "alzgg: create: missing output "
                        "(alzgg create archive.alz INPUTS...)\n");
        free(v);
        usage(2);
    }
    if (fmt == FMT_NONE) fmt = fmt_from_path(out);
    if (fmt == FMT_NONE) {
        fprintf(stderr, "alzgg: create: cannot tell the format of '%s' "
                        "(expected .alz or .egg, or --format alz|egg)\n", out);
        free(v);
        return 2;
    }

    /* A positional output may not overwrite an input: that is exactly the
     * ambiguity the `alzgg create OUTPUT …` form introduces. -o stays explicit
     * and may replace an existing file. */
    if (o_i < 0 && access(out, F_OK) == 0) {
        fprintf(stderr, "alzgg: create: '%s' already exists; use -o to "
                        "overwrite it explicitly, or name a new output\n",
                out);
        free(v);
        return 2;
    }
    for (i = 0; i < n; ++i) {
        if (o_i >= 0 ? (i == o_i || i == o_i + 1) : i == out_i) continue;
        if (v[i][0] == '-' && v[i][1]) {
            if (takes_value(v[i]) && i + 1 < n) ++i;
            continue;
        }
        if (!strcmp(v[i], out)) {
            fprintf(stderr, "alzgg: create: the output '%s' is also an "
                            "input of the archive\n", out);
            free(v);
            return 2;
        }
    }

    fwd = calloc((size_t)n + 6, sizeof *fwd);
    if (!fwd) {
        fprintf(stderr, "alzgg: out of memory\n");
        free(v);
        return 2;
    }
    fwd[0] = argv[0];
    fwd[1] = (char *)"create";
    if (fmt == FMT_EGG) {
        int k = 2;
        fwd[k++] = (char *)out;
        /* Output already moved to argv[2]: drop it from the arguments — the
         * -o/value pair when present, the positional one otherwise. */
        for (i = 0; i < n; ++i) {
            if (o_i >= 0 ? (i == o_i || i == o_i + 1) : i == out_i) continue;
            fwd[k++] = v[i];
        }
        rc = egg_cli_main(k, fwd);
    } else if (o_i >= 0) {
        int k = 2;
        for (i = 0; i < n; ++i) fwd[k++] = v[i];
        rc = alz_cli_main(k, fwd);
    } else {
        int k = 2;
        fwd[k++] = (char *)"-o";
        fwd[k++] = (char *)out;
        for (i = 0; i < n; ++i)
            if (i != out_i) fwd[k++] = v[i];
        rc = alz_cli_main(k, fwd);
    }
    free(fwd);
    free(v);
    return rc;
}

static int is_bare_list(int argc, char **argv)
{
    if (argc < 2) return 0;
    int is_list = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "list")) {
            is_list = 1;
            break;
        }
        if (argv[i][0] != '-') break;
    }
    if (!is_list) return 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-1") || !strcmp(argv[i], "--bare")) return 1;
        if (argv[i][0] == '-' && argv[i][1] != '-' && argv[i][1] != '\0') {
            int has_bare = 0, all_flags = 1;
            for (const char *p = argv[i] + 1; *p; ++p) {
                if (*p == '1' || *p == 'b' || *p == 'B') has_bare = 1;
                else if (*p != 'u' && *p != 'U') { all_flags = 0; break; }
            }
            if (has_bare && all_flags) return 1;
        }
    }
    return 0;
}

static int dispatch_simple(int argc, char **argv, int forced)
{
    int fmt = forced;
    char **fwd = dup_args(argv, argc);
    const char *arc_path = NULL;
    int rc;

    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "-p")) {
            if (i + 1 < argc) ++i;
            continue;
        }
        if (argv[i][0] == '-') continue;
        arc_path = argv[i];
        break;
    }

    if (!arc_path) {
        fprintf(stderr, "alzgg: %s: missing archive\n", argv[1]);
        free(fwd);
        return 2;
    }

    if (fmt == FMT_NONE) fmt = fmt_from_magic(arc_path);
    /* Unreadable magic (truncated or corrupt file): the extension decides, so
     * that the reader of the right format reports the refusal. */
    if (fmt == FMT_NONE) fmt = fmt_from_path(arc_path);
    if (fmt == FMT_NONE) {
        fprintf(stderr, "alzgg: '%s' is neither an ALZ nor an EGG archive "
                        "(unknown extension or unreadable file); "
                        "--format alz|egg forces the reader\n", arc_path);
        free(fwd);
        return 2;
    }
    rc = fmt == FMT_ALZ ? alz_cli_main(argc, fwd) : egg_cli_main(argc, fwd);
    free(fwd);
    return rc;
}

int main(int argc, char **argv)
{
    if (!is_bare_list(argc, argv)) {
        print_header();
    }

    char **a = calloc((size_t)argc + 1, sizeof *a);
    int n = 0, i, forced = FMT_NONE, rc;

    if (!a) {
        fprintf(stderr, "alzgg: out of memory\n");
        return 2;
    }
    for (i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--format")) {
            const char *f = i + 1 < argc ? argv[++i] : NULL;

            if (!f) {
                fprintf(stderr, "alzgg: --format expects alz or egg\n");
                return 2;
            }
            if (!strcmp(f, "alz"))        forced = FMT_ALZ;
            else if (!strcmp(f, "egg"))   forced = FMT_EGG;
            else {
                fprintf(stderr, "alzgg: unknown --format '%s' (alz|egg)\n", f);
                return 2;
            }
            continue;
        }
        a[n++] = argv[i];
    }
    if (n < 3) usage(n >= 2 && (!strcmp(a[1], "-h") || !strcmp(a[1], "--help") ||
                               !strcmp(a[1], "help")) ? 0 : 2);
    if (!strcmp(a[1], "create"))  rc = dispatch_create(n, a, forced);
    else if (!strcmp(a[1], "list") || !strcmp(a[1], "extract"))
                                  rc = dispatch_simple(n, a, forced);
    else {
        fprintf(stderr, "alzgg: unknown sub-command: %s\n", a[1]);
        usage(2);
    }
    free(a);
    return rc;
}
