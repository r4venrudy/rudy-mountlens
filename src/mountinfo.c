#include "mountinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ML_MAX_BYTES (32U * 1024U * 1024U)
#define ML_MAX_LINE 65536U
#define ML_MAX_MOUNTS 100000U

static int read_bytes(FILE *file, ml_snapshot *snapshot, size_t *used, ml_error *error)
{
    char buffer[16384];
    size_t capacity = 0;
    size_t count;
    while ((count = fread(buffer, 1, sizeof buffer, file)) != 0) {
        if (count > ML_MAX_BYTES - *used) {
            error->message = "snapshot exceeds 32 MiB";
            return 0;
        }
        if (*used + count + 1 > capacity) {
            capacity = capacity ? capacity * 2 : sizeof buffer + 1;
            if (capacity < *used + count + 1) capacity = *used + count + 1;
            if (capacity > ML_MAX_BYTES + 1) capacity = ML_MAX_BYTES + 1;
            char *next = realloc(snapshot->bytes, capacity);
            if (!next) {
                error->message = "out of memory";
                return 0;
            }
            snapshot->bytes = next;
        }
        memcpy(snapshot->bytes + *used, buffer, count);
        *used += count;
    }
    if (ferror(file) || !*used) {
        error->message = ferror(file) ? "cannot read snapshot" : "empty snapshot";
        return 0;
    }
    snapshot->bytes[*used] = 0;
    return 1;
}

static int number(const char *text, uint32_t *value)
{
    uint32_t parsed = 0;
    if (!*text) return 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return 0;
        const uint32_t digit = (uint32_t)(*text - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) return 0;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return 1;
}

static char *token(char **cursor)
{
    char *start = *cursor;
    while (*start == ' ') ++start;
    if (!*start) return NULL;
    char *end = start;
    while (*end && *end != ' ') ++end;
    if (*end) *end++ = 0;
    *cursor = end;
    return start;
}

static int decode(char *text)
{
    char *out = text;
    while (*text) {
        if (*text != '\\') {
            *out++ = *text++;
            continue;
        }
        ++text;
        if (!strncmp(text, "040", 3)) *out++ = ' ';
        else if (!strncmp(text, "011", 3)) *out++ = '\t';
        else if (!strncmp(text, "012", 3)) *out++ = '\n';
        else if (!strncmp(text, "134", 3)) *out++ = '\\';
        else return 0;
        text += 3;
    }
    *out = 0;
    return 1;
}

static int absolute_path(const char *text)
{
    if (*text++ != '/') return 0;
    if (!*text) return 1;
    for (;;) {
        const char *end = strchr(text, '/');
        const size_t length = end ? (size_t)(end - text) : strlen(text);
        if (!length || (length == 1 && text[0] == '.') ||
            (length == 2 && text[0] == '.' && text[1] == '.')) return 0;
        if (!end) return 1;
        text = end + 1;
    }
}

static int flags(const char *text, unsigned *value)
{
    unsigned mode = 0;
    for (;;) {
        const char *end = strchr(text, ',');
        const size_t length = end ? (size_t)(end - text) : strlen(text);
        if (!length) return 0;
        if (length == 2 && !strncmp(text, "ro", 2)) {
            if (mode) return 0;
            mode = 1;
            *value |= ML_RO;
        } else if (length == 2 && !strncmp(text, "rw", 2)) {
            if (mode) return 0;
            mode = 2;
        } else if (length == 6 && !strncmp(text, "nosuid", 6)) *value |= ML_NOSUID;
        else if (length == 5 && !strncmp(text, "nodev", 5)) *value |= ML_NODEV;
        else if (length == 6 && !strncmp(text, "noexec", 6)) *value |= ML_NOEXEC;
        if (!end) return mode != 0;
        text = end + 1;
    }
}

static int optional(ml_mount *mount, const char *field)
{
    uint32_t *value = NULL;
    const char *data = NULL;
    if (!strncmp(field, "shared:", 7)) {
        value = &mount->shared; data = field + 7; mount->propagation |= ML_SHARED;
    } else if (!strncmp(field, "master:", 7)) {
        value = &mount->master; data = field + 7; mount->propagation |= ML_SLAVE;
    } else if (!strncmp(field, "propagate_from:", 15)) {
        value = &mount->propagate_from; data = field + 15;
    } else if (!strcmp(field, "unbindable")) {
        if (mount->propagation & ML_UNBINDABLE) return 0;
        mount->propagation |= ML_UNBINDABLE;
    } else if (!strcmp(field, "shared") || !strcmp(field, "master") ||
               !strcmp(field, "propagate_from") || !strncmp(field, "unbindable:", 11)) {
        return 0;
    }
    return !value || (!*value && number(data, value) && *value != 0);
}

static const char *parse(char *cursor, ml_mount *mount)
{
    char *id = token(&cursor), *parent = token(&cursor), *device = token(&cursor);
    char *root = token(&cursor), *target = token(&cursor), *options = token(&cursor);
    if (!options) return "missing fixed mount fields";
    char *minor = strchr(device, ':');
    if (!minor) return "invalid major:minor";
    *minor++ = 0;
    if (!number(id, &mount->id) || !mount->id ||
        !number(parent, &mount->parent) || !mount->parent ||
        !number(device, &mount->major) || !number(minor, &mount->minor)) return "invalid mount identifier or device";
    if (!decode(root) || !decode(target) || !absolute_path(root) || !absolute_path(target))
        return "invalid escaped root or target path";
    if (!flags(options, &mount->mount_flags)) return "invalid per-mount options";
    char *field;
    while ((field = token(&cursor)) && strcmp(field, "-")) {
        if (!optional(mount, field)) return "invalid or repeated propagation field";
    }
    if (!field) return "missing mountinfo separator";
    char *filesystem = token(&cursor), *source = token(&cursor), *super = token(&cursor);
    if (!super || token(&cursor)) return "expected filesystem, source, and superblock options";
    if (!decode(filesystem) || !decode(source) || !flags(super, &mount->super_flags))
        return "invalid filesystem, escaped source, or superblock options";
    if ((mount->propagation & ML_UNBINDABLE) && (mount->propagation & (ML_SHARED | ML_SLAVE)))
        return "incompatible propagation fields";
    mount->root = root; mount->target = target; mount->filesystem = filesystem;
    mount->source = source; mount->mount_options = options; mount->super_options = super;
    return NULL;
}

static int by_id(const void *a, const void *b)
{
    const ml_mount *first = a, *second = b;
    return (first->id > second->id) - (first->id < second->id);
}

static int by_target(const void *a, const void *b)
{
    const ml_mount *const *first = a;
    const ml_mount *const *second = b;
    const int order = strcmp((*first)->target, (*second)->target);
    return order ? order : by_id(*first, *second);
}

static int by_group(const void *a, const void *b)
{
    const ml_mount *const *first = a;
    const ml_mount *const *second = b;
    return ((*first)->shared > (*second)->shared) - ((*first)->shared < (*second)->shared);
}

static int topology(ml_snapshot *snapshot, ml_error *error)
{
    ml_mount *mounts = snapshot->mounts;
    const size_t count = snapshot->count;
    qsort(mounts, count, sizeof *mounts, by_id);
    for (size_t i = 0; i < count; ++i) {
        ml_mount *mount = &mounts[i];
        error->line = mount->line;
        if (i && mounts[i - 1].id == mount->id) {
            error->message = "duplicate mount ID";
            return 0;
        }
        mount->parent_index = count;
        if (mount->id == mount->parent) {
            if (strcmp(mount->target, "/")) {
                error->message = "self-parent mount has a non-root target";
                return 0;
            }
            continue;
        }
        const ml_mount key = {.id = mount->parent};
        ml_mount *parent = bsearch(&key, mounts, count, sizeof *mounts, by_id);
        if (parent) {
            mount->parent_index = (size_t)(parent - mounts);
            if (!strcmp(parent->target, mount->target)) parent->shadowed = 1;
        }
    }

    size_t *trail = malloc(count * sizeof *trail);
    snapshot->targets = malloc(count * sizeof *snapshot->targets);
    if (!trail || !snapshot->targets) {
        free(trail);
        error->message = "out of memory";
        return 0;
    }
    for (size_t i = 0; i < count; ++i) {
        size_t node = i, length = 0;
        while (node < count && !mounts[node].mark) {
            mounts[node].mark = 1;
            trail[length++] = node;
            node = mounts[node].parent_index;
        }
        if (node < count && mounts[node].mark == 1) {
            error->line = mounts[node].line;
            error->message = "mount parent cycle";
            free(trail);
            return 0;
        }
        size_t depth = node < count ? mounts[node].depth + 1 : 0;
        while (length) {
            node = trail[--length];
            mounts[node].depth = depth++;
            mounts[node].mark = 2;
        }
        snapshot->targets[i] = &mounts[i];
    }
    free(trail);
    qsort(snapshot->targets, count, sizeof *snapshot->targets, by_group);
    for (size_t start = 0; start < count;) {
        size_t end = start + 1;
        const uint32_t group = snapshot->targets[start]->shared;
        while (end < count && snapshot->targets[end]->shared == group) ++end;
        if (group) {
            for (size_t i = start; i < end; ++i) snapshot->targets[i]->shared_peers = end - start;
        }
        start = end;
    }
    qsort(snapshot->targets, count, sizeof *snapshot->targets, by_target);
    return 1;
}

int ml_read(const char *path, ml_snapshot *snapshot, ml_error *error)
{
    *snapshot = (ml_snapshot){0};
    *error = (ml_error){0};
    FILE *file = fopen(path, "rb");
    if (!file) {
        error->message = "cannot open snapshot";
        return 0;
    }
    size_t used = 0;
    const int loaded = read_bytes(file, snapshot, &used, error);
    fclose(file);
    if (!loaded) goto failed;
    size_t capacity = 0;
    for (char *line = snapshot->bytes; line < snapshot->bytes + used;) {
        char *end = memchr(line, '\n', (size_t)(snapshot->bytes + used - line));
        char *next = end ? end + 1 : snapshot->bytes + used;
        if (!end) end = next;
        if (end > line && end[-1] == '\r') --end;
        error->line = snapshot->count + 1;
        if ((size_t)(end - line) > ML_MAX_LINE || snapshot->count == ML_MAX_MOUNTS) {
            error->message = "snapshot exceeds line or record limit";
            goto failed;
        }
        for (char *byte = line; byte < end; ++byte) {
            if ((unsigned char)*byte < 32) {
                error->message = "unescaped control byte";
                goto failed;
            }
        }
        *end = 0;
        if (snapshot->count == capacity) {
            capacity = capacity ? capacity * 2 : 128;
            if (capacity > ML_MAX_MOUNTS) capacity = ML_MAX_MOUNTS;
            ml_mount *more = realloc(snapshot->mounts, capacity * sizeof *more);
            if (!more) {
                error->message = "out of memory";
                goto failed;
            }
            snapshot->mounts = more;
        }
        ml_mount *mount = &snapshot->mounts[snapshot->count];
        *mount = (ml_mount){.line = error->line};
        error->message = parse(line, mount);
        if (error->message) goto failed;
        ++snapshot->count;
        line = next;
    }
    if (topology(snapshot, error)) return 1;
failed:
    ml_free(snapshot);
    return 0;
}

void ml_free(ml_snapshot *snapshot)
{
    free(snapshot->targets);
    free(snapshot->mounts);
    free(snapshot->bytes);
    *snapshot = (ml_snapshot){0};
}

unsigned ml_restrictions(const ml_mount *mount)
{
    return mount->mount_flags | (mount->super_flags & ML_RO);
}
