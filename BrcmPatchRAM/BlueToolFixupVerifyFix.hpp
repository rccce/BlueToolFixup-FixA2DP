//
//  BlueToolFixupVerifyFix.hpp
//  BrcmPatchRAM
//
//  "verify-fix" for BlueToolFixup (AX210 report, section 12 and appendix G).
//  Keeps bluetoothd from crash-looping with "Data hash mismatch" (EBADMSG, SIGBUS) on macOS 26,
//  where APFS verifies compressed system files in 16 KB blocks that include pages we patched.
//
//  Use: put this file next to BlueToolFixup.cpp and make three small edits there (4 lines in total):
//   1. after  #define MODULE_SHORT "btlfx"
//          #include "BlueToolFixupVerifyFix.hpp"
//   2. first line inside  if (vn_getpath(vp, path, &pathlen) == 0 && ...) {  in patched_cs_validate_page()
//          VerifyFix::PatchRecorder recorder(vp, page_offset, data, path);
//   3. after  SYSLOG(MODULE_SHORT, "failed to route cs validation pages");  in pluginStart()
//          else
//              VerifyFix::init(patcher);
//
//  Written for the hexxyan/BlueToolFixup-FixA2DP fork (branch fix-a2dp-fastconnect, d8bd62a); the same
//  three edits also apply to acidanthera/BrcmPatchRAM master (4fdd4d4). The file relies only on the Lilu
//  headers and MODULE_SHORT, which BlueToolFixup.cpp provides before the include.
//  Status: C++ syntax-checked against stub headers; logic checked with a step-by-step Python model.
//  NOT compiled with Xcode, NOT tested on macOS.
//

#ifndef BlueToolFixupVerifyFix_hpp
#define BlueToolFixupVerifyFix_hpp

#include <IOKit/IOLocks.h>
#include <kern/thread_call.h>
#include <sys/errno.h>
#include <sys/ubc.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>

#pragma mark - Verify fix

//
// Why this exists
// ---------------
// patched_cs_validate_page() patches the page that sits in the shared file cache (UBC), so every
// mapping and every read() of /usr/sbin/bluetoothd sees the patched bytes. On x86_64 (4 KB pages),
// APFS verifies compressed files on the sealed system volume in 16 KB blocks. When only part of such
// a block has to be paged in again, decmpfs hashes the whole block, including the pages that are
// still resident. If one of them is a patched page, the hash cannot match: the page-in fails with
// EBADMSG (94), bluetoothd dies with SIGBUS, and it keeps dying for as long as the patched page stays
// resident (in practice until reboot).
//
// Layer 1 (verify): wrap VNOP_VERIFY. When a block of a tracked file still contains bytes that we
//   patched, verify a private copy of that block in which exactly those bytes are put back to their
//   recorded original values. The live pages are never written, so running threads are unaffected,
//   and any other difference from the sealed data is still detected.
// Layer 2 (heal): wrap decmpfs_pagein_compressed. If a page-in of a tracked file still fails with
//   EBADMSG (for example because the VNOP_VERIFY call could not be intercepted), drop the cached
//   pages of that file from a thread call. The next fault pages whole blocks in again (all pages
//   absent, so the hash matches) and bluetoothd recovers without a reboot.
//
// Boot-args: -btlfxnoverify disables layer 1, -btlfxnoheal disables layer 2.
//

namespace VerifyFix {

static constexpr size_t MaxSites     = 32;
static constexpr size_t MaxSiteBytes = 24;
static constexpr size_t MaxFiles     = 2;
static constexpr size_t MaxVerifyBlk = 64 * 1024;
static constexpr size_t MergeGap     = 8;

struct Site {
	vnode_t  vp;      // identity only, never dereferenced
	uint32_t vid;
	uint32_t len;
	uint64_t off;     // offset in the file (= offset in the vnode's memory object)
	uint8_t  orig[MaxSiteBytes];
	uint8_t  patched[MaxSiteBytes];
};

struct File {
	vnode_t  vp;
	uint32_t vid;
	bool     healPending;
	char     path[32];
};

static Site sites[MaxSites];
static size_t siteCount;
static File files[MaxFiles];
static size_t fileCount;           // published with release stores, read without the lock
static IOLock *lock;               // sites, files, snapshot
static IOLock *scratchLock;        // scratch
static uint8_t snapshot[PAGE_SIZE];
static uint8_t scratch[MaxVerifyBlk];
static thread_call_t healCall;
static bool tracking, verifyOn, healOn, verifySeen;
static mach_vm_address_t orgVerify, orgPagein;

// Hot path (every VNOP_VERIFY / compressed page-in in the system): pointer compares only;
// vnode_vid() is called only for a pointer that matches, on a vnode the caller holds.
static bool lookupFile(vnode_t vp, size_t *index) {
	size_t n = __atomic_load_n(&fileCount, __ATOMIC_ACQUIRE);
	for (size_t i = 0; i < n; i++) {
		if (files[i].vp == vp && files[i].vid == static_cast<uint32_t>(vnode_vid(vp))) {
			if (index) *index = i;
			return true;
		}
	}
	return false;
}

static void registerFileLocked(vnode_t vp, uint32_t vid, const char *path) {
	for (size_t i = 0; i < fileCount; i++) {
		if (strcmp(files[i].path, path) == 0) {
			files[i].vid = vid;   // the vnode may have been recycled and looked up again
			files[i].vp = vp;
			return;
		}
	}
	if (fileCount < MaxFiles) {
		File &f = files[fileCount];
		f.vp = vp;
		f.vid = vid;
		f.healPending = false;
		strlcpy(f.path, path, sizeof(f.path));
		__atomic_store_n(&fileCount, fileCount + 1, __ATOMIC_RELEASE);
	}
}

static bool siteIsCurrentLocked(const Site &s) {
	for (size_t i = 0; i < fileCount; i++)
		if (files[i].vp == s.vp && files[i].vid == s.vid)
			return true;
	return false;
}

static void addSiteLocked(vnode_t vp, uint32_t vid, uint64_t off, const uint8_t *orig, const uint8_t *patched, size_t len) {
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (s.vp == vp && s.vid == vid && s.off == off && s.len == len)
			return;   // the page was paged in again and re-patched: already known
	}
	Site *s = nullptr;
	if (siteCount < MaxSites) {
		s = &sites[siteCount++];
	} else {
		for (size_t i = 0; i < siteCount && s == nullptr; i++)
			if (!siteIsCurrentLocked(sites[i]))
				s = &sites[i];   // reuse a slot of an old vnode generation
	}
	if (s == nullptr) {
		SYSLOG(MODULE_SHORT, "verify-fix: site table full, 0x%llx not recorded", off);
		return;
	}
	s->vp = vp;
	s->vid = vid;
	s->off = off;
	s->len = static_cast<uint32_t>(len);
	memcpy(s->orig, orig, len);
	memcpy(s->patched, patched, len);
	SYSLOG(MODULE_SHORT, "verify-fix: recorded patch site 0x%llx (%lu bytes)", off, static_cast<unsigned long>(len));
}

// Compare the page before and after our patches and remember every changed byte run, so that the
// exact original bytes can be put back later. Works for any current or future patch in this file.
static void recordLocked(vnode_t vp, const char *path, uint64_t pageOff, const uint8_t *before, const uint8_t *after) {
	uint32_t vid = static_cast<uint32_t>(vnode_vid(vp));
	bool registered = false;
	for (size_t i = 0; i < PAGE_SIZE; ) {
		if (before[i] == after[i]) {
			i++;
			continue;
		}
		size_t start = i, last = i;
		for (size_t j = i + 1; j < PAGE_SIZE && j - start < MaxSiteBytes; j++) {
			if (before[j] != after[j])
				last = j;
			else if (j - last > MergeGap)
				break;
		}
		if (!registered) {
			registerFileLocked(vp, vid, path);
			registered = true;
		}
		addSiteLocked(vp, vid, pageOff + start, before + start, after + start, last - start + 1);
		i = last + 1;
	}
}

// Sites never cross a 4 KB page, so they never cross a verify block either.
static bool siteInRange(const Site &s, vnode_t vp, uint32_t vid, uint64_t foff, size_t len) {
	return s.vp == vp && s.vid == vid && s.off >= foff && s.off + s.len <= foff + len;
}

static size_t countPatchedLocked(vnode_t vp, uint32_t vid, uint64_t foff, const uint8_t *buf, size_t len) {
	size_t n = 0;
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (siteInRange(s, vp, vid, foff, len) && memcmp(buf + (s.off - foff), s.patched, s.len) == 0)
			n++;
	}
	return n;
}

static size_t restoreLocked(vnode_t vp, uint32_t vid, uint64_t foff, uint8_t *buf, size_t len) {
	size_t bytes = 0;
	for (size_t i = 0; i < siteCount; i++) {
		const Site &s = sites[i];
		if (siteInRange(s, vp, vid, foff, len) && memcmp(buf + (s.off - foff), s.patched, s.len) == 0) {
			memcpy(buf + (s.off - foff), s.orig, s.len);
			bytes += s.len;
		}
	}
	return bytes;
}

// callOrg(foff, buf, size, &verifyBlockSize) calls the original VNOP_VERIFY with the other
// arguments unchanged. Clean runs of blocks are verified in place; each block that still holds
// patched bytes is verified from a copy with those bytes restored.
template <typename F>
static errno_t verifyTracked(vnode_t vp, off_t foff, uint8_t *buf, size_t bufsize, size_t *vbsp, F callOrg) {
	size_t vbs = *vbsp;
	if (foff < 0 || vbs == 0 || vbs > MaxVerifyBlk || (vbs & (vbs - 1)) != 0 || (static_cast<uint64_t>(foff) & (vbs - 1)) != 0)
		return callOrg(foff, buf, bufsize, vbsp);

	uint32_t vid = static_cast<uint32_t>(vnode_vid(vp));
	IOLockLock(lock);
	size_t dirty = countPatchedLocked(vp, vid, static_cast<uint64_t>(foff), buf, bufsize);
	IOLockUnlock(lock);
	if (dirty == 0)
		return callOrg(foff, buf, bufsize, vbsp);

	errno_t err = 0;
	size_t off = 0, clean = 0;   // [clean, off) is a run of blocks without patched bytes
	while (off < bufsize && err == 0) {
		size_t len = bufsize - off < vbs ? bufsize - off : vbs;
		IOLockLock(lock);
		bool blockDirty = countPatchedLocked(vp, vid, static_cast<uint64_t>(foff) + off, buf + off, len) != 0;
		IOLockUnlock(lock);
		if (blockDirty) {
			if (off > clean) {
				size_t v = vbs;
				err = callOrg(foff + static_cast<off_t>(clean), buf + clean, off - clean, &v);
				if (err != 0)
					break;
			}
			IOLockLock(scratchLock);
			memcpy(scratch, buf + off, len);
			IOLockLock(lock);
			size_t restored = restoreLocked(vp, vid, static_cast<uint64_t>(foff) + off, scratch, len);
			IOLockUnlock(lock);
			size_t v = vbs;
			err = callOrg(foff + static_cast<off_t>(off), scratch, len, &v);
			IOLockUnlock(scratchLock);
			SYSLOG(MODULE_SHORT, "verify-fix: block 0x%llx verified with %lu original byte(s) restored, error %d",
				   static_cast<uint64_t>(foff) + off, static_cast<unsigned long>(restored), err);
			clean = off + len;
		}
		off += len;
	}
	if (err == 0 && clean < bufsize) {
		size_t v = vbs;
		err = callOrg(foff + static_cast<off_t>(clean), buf + clean, bufsize - clean, &v);
	}
	return err;
}

//
// VNOP_VERIFY wrapper.
// The prototype of VNOP_VERIFY has grown over macOS releases, but its first five parameters
// (vp, foff, buf, bufsize, verify_block_size) have stayed the same. The wrapper therefore takes
// five extra integer/pointer-sized arguments and forwards them untouched: on x86_64 (System V ABI)
// a callee simply ignores trailing arguments it does not declare, and reading unused stack slots of
// the caller is harmless. The wrapper only takes over when arguments 6 and 7 are zero, i.e. a plain
// synchronous verification without a verify context, which is how decmpfs verifies page-ins.
// Anything else is passed through unchanged.
//
using VerifyFn = errno_t (*)(vnode_t, off_t, uint8_t *, size_t, size_t *, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

static errno_t wrapVerify(vnode_t vp, off_t foff, uint8_t *buf, size_t bufsize, size_t *vbs,
						  uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9, uintptr_t a10) {
	auto org = reinterpret_cast<VerifyFn>(orgVerify);
	if (buf == nullptr || bufsize == 0 || vbs == nullptr || !lookupFile(vp, nullptr))
		return org(vp, foff, buf, bufsize, vbs, a6, a7, a8, a9, a10);
	if (!__atomic_exchange_n(&verifySeen, true, __ATOMIC_RELAXED))
		SYSLOG(MODULE_SHORT, "verify-fix: VNOP_VERIFY seen for a tracked file (0x%llx, %lu bytes, block %lu, a6 0x%lx, a7 0x%lx)",
			   static_cast<uint64_t>(foff), static_cast<unsigned long>(bufsize), static_cast<unsigned long>(*vbs), static_cast<unsigned long>(a6), static_cast<unsigned long>(a7));
	if (a6 != 0 || a7 != 0)
		return org(vp, foff, buf, bufsize, vbs, a6, a7, a8, a9, a10);
	return verifyTracked(vp, foff, buf, bufsize, vbs, [&](off_t o, uint8_t *b, size_t s, size_t *v) {
		return org(vp, o, b, s, v, a6, a7, a8, a9, a10);
	});
}

//
// Layer 2: self-heal.
//
static void healCallback(thread_call_param_t, thread_call_param_t) {
	size_t n = __atomic_load_n(&fileCount, __ATOMIC_ACQUIRE);
	for (size_t i = 0; i < n; i++) {
		if (!__atomic_exchange_n(&files[i].healPending, false, __ATOMIC_ACQ_REL))
			continue;
		vfs_context_t ctx = vfs_context_create(nullptr);
		vnode_t vp = NULLVP;
		errno_t err = vnode_lookup(files[i].path, 0, &vp, ctx);
		if (err == 0) {
			// Clean, unwired pages are unmapped and freed; pages wired by mlock (vmtouch -l) stay.
			err = ubc_msync(vp, 0, ubc_getsize(vp), nullptr, UBC_INVALIDATE);
			vnode_put(vp);
		}
		vfs_context_rele(ctx);
		SYSLOG(MODULE_SHORT, "self-heal: dropped cached pages of %s, result %d", files[i].path, err);
	}
}

static int wrapPagein(struct vnop_pagein_args *ap, int *isCompressed, void *cp) {
	int err = FunctionCast(wrapPagein, orgPagein)(ap, isCompressed, cp);
	size_t i = 0;
	if (UNLIKELY(err == EBADMSG) && healOn && ap != nullptr && lookupFile(ap->a_vp, &i)) {
		SYSLOG(MODULE_SHORT, "self-heal: page-in of %s at 0x%llx failed with EBADMSG, dropping its cached pages",
			   files[i].path, static_cast<uint64_t>(ap->a_f_offset));
		__atomic_store_n(&files[i].healPending, true, __ATOMIC_RELEASE);
		thread_call_enter(healCall);
	}
	return err;
}

static void init(KernelPatcher &patcher) {
	const bool wantVerify = !checkKernelArgument("-btlfxnoverify");
	const bool wantHeal = !checkKernelArgument("-btlfxnoheal");
	if (!wantVerify && !wantHeal)
		return;

	lock = IOLockAlloc();
	scratchLock = IOLockAlloc();
	healCall = thread_call_allocate(healCallback, nullptr);
	if (lock == nullptr || scratchLock == nullptr || healCall == nullptr) {
		SYSLOG(MODULE_SHORT, "verify-fix: allocation failed, disabled");
		return;
	}

	if (wantHeal) {
		KernelPatcher::RouteRequest req("_decmpfs_pagein_compressed", wrapPagein, orgPagein);
		healOn = patcher.routeMultipleLong(KernelPatcher::KernelID, &req, 1);
		if (!healOn)
			patcher.clearError();
	}

	if (wantVerify) {
		KernelPatcher::RouteRequest req("_VNOP_VERIFY", wrapVerify, orgVerify);
		verifyOn = patcher.routeMultipleLong(KernelPatcher::KernelID, &req, 1);
		if (!verifyOn)
			patcher.clearError();
	}

	tracking = verifyOn || healOn;
	SYSLOG(MODULE_SHORT, "verify-fix: verify layer %s, heal layer %s", verifyOn ? "on" : "off", healOn ? "on" : "off");
}

//
// Patch recorder: the only hook into the patch code. One line in patched_cs_validate_page(),
// right after its "/usr/sbin/" path check:
//
//     VerifyFix::PatchRecorder recorder(vp, page_offset, data, path);
//
// For bluetoothd and BlueTool it copies the page before the patches run. When it goes out of scope,
// after the last patch of that page, it records every byte run that the patches changed. So every
// patch in BlueToolFixup.cpp is covered, including patches added later (for example the Fast-Connect
// A2DP gate of the BlueToolFixup-FixA2DP fork), without changing any patch code.
//
class PatchRecorder {
	vnode_t mVnode;
	uint64_t mOffset;
	const uint8_t *mPage;
	const char *mPath;
	bool mActive {false};

public:
	PatchRecorder(vnode_t vp, memory_object_offset_t pageOffset, const void *data, const char *path)
		: mVnode(vp), mOffset(pageOffset), mPage(static_cast<const uint8_t *>(data)), mPath(path) {
		static constexpr size_t dirLength = sizeof("/usr/sbin/") - 1;
		if (!tracking || mPage == nullptr || path == nullptr || strncmp(path, "/usr/sbin/", dirLength) != 0)
			return;
		const char *name = path + dirLength;
		if (strcmp(name, "bluetoothd") != 0 && strcmp(name, "BlueTool") != 0)
			return;
		mActive = true;
		IOLockLock(lock);
		memcpy(snapshot, mPage, PAGE_SIZE);
	}

	~PatchRecorder() {
		if (!mActive)
			return;
		recordLocked(mVnode, mPath, mOffset, snapshot, mPage);
		IOLockUnlock(lock);
	}

	PatchRecorder(const PatchRecorder &) = delete;
	PatchRecorder &operator=(const PatchRecorder &) = delete;
};

} // namespace VerifyFix

#endif /* BlueToolFixupVerifyFix_hpp */
