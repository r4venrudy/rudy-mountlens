#include "mountinfo.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define VERSION "0.1.0-preview"

static const char *truth(int value) { return value ? "true" : "false"; }

static void string(const char *text)
{
    if (!text) {
        fputs("null", stdout);
        return;
    }
    putchar('"');
    for (const unsigned char *byte = (const unsigned char *)text; *byte; ++byte) {
        if (*byte == '"' || *byte == '\\') printf("\\%c", *byte);
        else if (*byte < 32 || *byte >= 127) printf("\\u%04x", (unsigned)*byte);
        else putchar(*byte);
    }
    putchar('"');
}

static void restrictions(unsigned flags)
{
    printf("{\"readOnly\":%s,\"nosuid\":%s,\"nodev\":%s,\"noexec\":%s}",
           truth((flags & ML_RO) != 0), truth((flags & ML_NOSUID) != 0),
           truth((flags & ML_NODEV) != 0), truth((flags & ML_NOEXEC) != 0));
}

static const char *parent_target(const ml_snapshot *snapshot, const ml_mount *mount)
{
    return mount->parent_index < snapshot->count ? snapshot->mounts[mount->parent_index].target : NULL;
}

static void record(const ml_snapshot *snapshot, const ml_mount *mount)
{
    if (!mount) {
        fputs("null", stdout);
        return;
    }
    const char *parent = parent_target(snapshot, mount);
    const char *relation = parent ? "attached" : mount->id == mount->parent ? "self-root" : "outside-snapshot";
    printf("{\"id\":%" PRIu32 ",\"parentId\":%" PRIu32 ",\"parentRelation\":\"%s\",\"parentTarget\":",
           mount->id, mount->parent, relation);
    string(parent);
    printf(",\"depth\":%zu,\"shadowedAtTarget\":%s,\"device\":\"%" PRIu32 ":%" PRIu32 "\",\"root\":",
           mount->depth, truth(mount->shadowed), mount->major, mount->minor);
    string(mount->root);
    fputs(",\"target\":", stdout); string(mount->target);
    fputs(",\"filesystem\":", stdout); string(mount->filesystem);
    fputs(",\"source\":", stdout); string(mount->source);
    fputs(",\"mountOptions\":", stdout); string(mount->mount_options);
    fputs(",\"superOptions\":", stdout); string(mount->super_options);
    fputs(",\"restrictions\":", stdout); restrictions(ml_restrictions(mount));
    printf(",\"propagation\":{\"shared\":%" PRIu32 ",\"master\":%" PRIu32
           ",\"propagateFrom\":%" PRIu32 ",\"unbindable\":%s,\"sharedPeersInSnapshot\":%zu}}",
           mount->shared, mount->master, mount->propagate_from,
           truth((mount->propagation & ML_UNBINDABLE) != 0), mount->shared_peers);
}

typedef struct {
    size_t count, candidates;
    const ml_mount *chosen;
} group;

static group take_group(const ml_snapshot *snapshot, size_t *index)
{
    group result = {0};
    const char *target = snapshot->targets[*index]->target;
    do {
        const ml_mount *mount = snapshot->targets[(*index)++];
        ++result.count;
        if (!mount->shadowed) {
            ++result.candidates;
            result.chosen = mount;
        }
    } while (*index < snapshot->count && !strcmp(target, snapshot->targets[*index]->target));
    if (result.candidates != 1) result.chosen = NULL;
    return result;
}

static void inspect(const ml_snapshot *snapshot)
{
    size_t external = 0, stacked = 0, ambiguous = 0, targets = 0;
    fputs("{\"schema\":1,\"mode\":\"inspect\",\"mounts\":[", stdout);
    for (size_t i = 0; i < snapshot->count; ++i) {
        const ml_mount *mount = &snapshot->mounts[i];
        if (i) putchar(',');
        record(snapshot, mount);
        external += (size_t)(mount->parent_index == snapshot->count && mount->id != mount->parent);
    }
    for (size_t i = 0; i < snapshot->count;) {
        const group next = take_group(snapshot, &i);
        ++targets;
        stacked += (size_t)(next.count > 1 && next.candidates == 1);
        ambiguous += (size_t)(next.candidates != 1);
    }
    printf("],\"counts\":{\"mounts\":%zu,\"targets\":%zu,\"externalParents\":%zu,"
           "\"directStacks\":%zu,\"ambiguousTargets\":%zu}}\n",
           snapshot->count, targets, external, stacked, ambiguous);
}

static int same(const char *first, const char *second)
{
    return first && second ? !strcmp(first, second) : first == second;
}

static int compare(const ml_snapshot *before, const ml_snapshot *after, int gate)
{
    size_t i = 0, j = 0, emitted = 0, unchanged = 0, added = 0, removed = 0;
    size_t changed = 0, ambiguous = 0, relaxed = 0;
    fputs("{\"schema\":1,\"mode\":\"compare\",\"changes\":[", stdout);
    while (i < before->count || j < after->count) {
        const char *left = i < before->count ? before->targets[i]->target : NULL;
        const char *right = j < after->count ? after->targets[j]->target : NULL;
        const int order = !left ? 1 : !right ? -1 : strcmp(left, right);
        const char *target = order <= 0 ? left : right;
        const group old = order <= 0 ? take_group(before, &i) : (group){0};
        const group next = order >= 0 ? take_group(after, &j) : (group){0};
        const char *status;
        unsigned lost = 0, gained = 0;
        int backing = 0, attachment = 0, propagation = 0;
        if (old.candidates > 1 || next.candidates > 1) {
            status = "ambiguous";
            ++ambiguous;
        } else if (!old.count) {
            status = "added";
            ++added;
        } else if (!next.count) {
            status = "removed";
            ++removed;
        } else {
            const ml_mount *a = old.chosen, *b = next.chosen;
            const unsigned previous = ml_restrictions(a), current = ml_restrictions(b);
            lost = previous & ~current;
            gained = current & ~previous;
            backing = a->major != b->major || a->minor != b->minor ||
                strcmp(a->source, b->source) || strcmp(a->root, b->root) || strcmp(a->filesystem, b->filesystem);
            attachment = !same(parent_target(before, a), parent_target(after, b)) ||
                (a->parent == a->id) != (b->parent == b->id);
            propagation = a->propagation != b->propagation || a->shared_peers != b->shared_peers ||
                (a->propagate_from != 0) != (b->propagate_from != 0);
            if (!lost && !gained && !backing && !attachment && !propagation && old.count == next.count) {
                ++unchanged;
                continue;
            }
            status = "changed";
            ++changed;
            if (lost) ++relaxed;
        }
        if (emitted++) putchar(',');
        fputs("{\"target\":", stdout); string(target);
        printf(",\"status\":\"%s\",\"beforeLayers\":%zu,\"afterLayers\":%zu,"
               "\"beforeCandidates\":%zu,\"afterCandidates\":%zu,\"before\":",
               status, old.count, next.count, old.candidates, next.candidates);
        record(before, old.chosen);
        fputs(",\"after\":", stdout); record(after, next.chosen);
        printf(",\"backingChanged\":%s,\"attachmentChanged\":%s,\"propagationChanged\":%s,\"lost\":",
               truth(backing), truth(attachment), truth(propagation));
        restrictions(lost);
        fputs(",\"gained\":", stdout); restrictions(gained);
        putchar('}');
    }
    printf("],\"counts\":{\"unchanged\":%zu,\"added\":%zu,\"removed\":%zu,\"changed\":%zu,"
           "\"ambiguous\":%zu,\"relaxed\":%zu}}\n", unchanged, added, removed, changed, ambiguous, relaxed);
    return gate ? relaxed ? 1 : ambiguous ? 3 : 0 : 0;
}

static int load(const char *path, ml_snapshot *snapshot)
{
    ml_error error;
    if (ml_read(path, snapshot, &error)) return 1;
    fprintf(stderr, "mountlens: %s at line %zu\n", error.message, error.line);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("mountlens " VERSION);
        return fflush(stdout) == 0 ? 0 : 2;
    }
    ml_snapshot before, after;
    int status = 0;
    if (argc == 3 && !strcmp(argv[1], "inspect")) {
        if (!load(argv[2], &before)) return 2;
        inspect(&before);
        ml_free(&before);
    } else if ((argc == 4 || (argc == 5 && !strcmp(argv[4], "--fail-on-relaxation"))) &&
               !strcmp(argv[1], "compare")) {
        if (!load(argv[2], &before)) return 2;
        if (!load(argv[3], &after)) {
            ml_free(&before);
            return 2;
        }
        status = compare(&before, &after, argc == 5);
        ml_free(&after);
        ml_free(&before);
    } else {
        fputs("mountlens: inspect SNAPSHOT | compare BEFORE AFTER [--fail-on-relaxation]\n", stderr);
        return 2;
    }
    return fflush(stdout) == 0 && !ferror(stdout) ? status : 2;
}
