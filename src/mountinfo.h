#ifndef MOUNTLENS_MOUNTINFO_H
#define MOUNTLENS_MOUNTINFO_H
#include <stddef.h>
#include <stdint.h>

enum {
    ML_RO = 1U, ML_NOSUID = 2U, ML_NODEV = 4U, ML_NOEXEC = 8U,
    ML_UNBINDABLE = 1U, ML_SHARED = 2U, ML_SLAVE = 4U
};

typedef struct {
    uint32_t id, parent, major, minor, shared, master, propagate_from;
    unsigned mount_flags, super_flags, propagation;
    size_t line, parent_index, depth, shared_peers;
    const char *root, *target, *filesystem, *source, *mount_options, *super_options;
    unsigned char mark;
    unsigned char shadowed;
} ml_mount;

typedef struct {
    char *bytes;
    ml_mount *mounts;
    ml_mount **targets;
    size_t count;
} ml_snapshot;

typedef struct {
    size_t line;
    const char *message;
} ml_error;

int ml_read(const char *path, ml_snapshot *snapshot, ml_error *error);
void ml_free(ml_snapshot *snapshot);
unsigned ml_restrictions(const ml_mount *mount);
#endif
