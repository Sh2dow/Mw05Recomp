// Fallback forward decls (temporary)
struct KernelObject;  // if used by Handle table entries

// Very lightweight handle-table view used by this file
struct HandleEntry {
    uint32_t type;
    KernelObject* ptr;
};

struct HandleTable {
    const HandleEntry* Lookup(uint32_t handle) const; // real impl elsewhere
};

extern HandleTable g_HandleTable;
