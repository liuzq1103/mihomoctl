//go:build linux

package routing

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeStat is a synthetic os.FileInfo carrying just the fields the ownership
// predicate reads: the mode and the stat uid. It lets the full ownership
// matrix run without provisioning or mutating any host account.
type fakeStat struct {
	mode os.FileMode
	uid  int
}

func (f fakeStat) Name() string       { return "resource" }
func (f fakeStat) Size() int64        { return 5 }
func (f fakeStat) Mode() os.FileMode  { return f.mode }
func (f fakeStat) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeStat) IsDir() bool        { return false }
func (f fakeStat) Sys() any           { return &syscall.Stat_t{Uid: uint32(f.uid)} }

// TestLinuxValidationResourceOwnershipMatrix covers every branch of the pure
// ownership predicate against synthetic stat data: no host mutation, no
// required accounts, no root. The production wrapper resolves the real
// service uid; here it is a parameter.
func TestLinuxValidationResourceOwnershipMatrix(t *testing.T) {
	self := os.Geteuid()
	const service = 9001
	cases := []struct {
		label    string
		uid      int
		mode     os.FileMode
		system   bool
		accepted bool
	}{
		// System scope: root, acting account, and the service account all
		// validate without group/other write — the delivered 0640
		// configuration and service-owned resources included.
		{"system root 0640", 0, 0640, true, true},
		{"system root 0644", 0, 0644, true, true},
		{"system root 0600", 0, 0600, true, true},
		{"system service 0600", service, 0600, true, true},
		{"system service 0640", service, 0640, true, true},
		{"system acting account 0600", self, 0600, true, true},
		{"system foreign 0600", 65534, 0600, true, false},
		{"system root group-writable", 0, 0660, true, false},
		{"system root other-writable", 0, 0606, true, false},
		{"system service group-writable", service, 0660, true, false},
		{"system service other-writable", service, 0602, true, false},
		{"system service other-readable", service, 0604, true, true},
		// A missing service account resolves to -1 and must match nothing.
		{"system unknown uid 0600", 4294967295, 0600, true, false},
		// User scope stays strict: own files, no group/other bits at all.
		{"user own 0600", self, 0600, false, true},
		{"user own 0640", self, 0640, false, false},
		{"user own 0660", self, 0660, false, false},
		{"user foreign 0600", 65534, 0600, false, false},
		{"user root-owned when root is foreign", 0, 0600, false, self == 0},
	}
	for _, testCase := range cases {
		owned := validationResourceOwnedBy(fakeStat{mode: testCase.mode, uid: testCase.uid}, testCase.system, service)
		if owned != testCase.accepted {
			t.Fatalf("%s: owned = %v, want %v", testCase.label, owned, testCase.accepted)
		}
	}
	// With the service account unresolvable (-1), a file owned by the very
	// same uid number the real account WOULD have must still be refused.
	if owned := validationResourceOwnedBy(fakeStat{mode: 0600, uid: 9001}, true, -1); owned {
		t.Fatal("system scope accepted service-uid file with no service account")
	}
}

// ownerFixture writes one file with an exact uid/gid and mode, returning its
// stat info for the production ownership predicate.
func ownerFixture(t *testing.T, directory string, index int, uid, gid int, mode os.FileMode) os.FileInfo {
	t.Helper()
	path := filepath.Join(directory, "resource-"+string(rune('a'+index)))
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Skipf("ownership %d:%d unstagedable: %v", uid, gid, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// provisionServiceAccount provisions the mihomoctl-go system account exactly
// like the runtime core's accountIdentity(true) and reports whether THIS
// call created it. When it creates the account, a cleanup is registered that
// removes only that account and its user-group — a pre-existing account is
// never touched, and the host is left as the test found it.
func provisionServiceAccount(t *testing.T) int {
	t.Helper()
	if uid := serviceAccountUID(); uid > 0 {
		return uid // pre-existing: never deleted
	}
	command := exec.Command("useradd", "--system", "--user-group",
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", goServiceAccount)
	if err := command.Run(); err != nil {
		return -1
	}
	uid := serviceAccountUID()
	if uid <= 0 {
		return -1
	}
	t.Cleanup(func() {
		// Best effort; only the account this test just created is removed.
		if err := exec.Command("userdel", goServiceAccount).Run(); err != nil {
			t.Logf("cleanup userdel %s: %v", goServiceAccount, err)
		}
		if err := exec.Command("groupdel", goServiceAccount).Run(); err != nil {
			t.Logf("cleanup groupdel %s: %v", goServiceAccount, err)
		}
	})
	return uid
}

// TestLinuxValidationResourceOwnershipSystem exercises the PRODUCTION
// predicate (real serviceAccountUID resolution) against real files with real
// staged ownerships: root-owned 0640 and service-owned 0600 validate, a
// foreign owner and group-writable files never do. Staging foreign
// ownerships requires root; the service account is provisioned only when
// absent, and anything provisioned is removed afterwards.
func TestLinuxValidationResourceOwnershipSystem(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("staging foreign ownerships requires root")
	}
	serviceUID := provisionServiceAccount(t)
	if serviceUID <= 0 {
		t.Skip("service account unavailable and unstagedable")
	}
	foreign := nobodyUID()
	if foreign <= 0 || foreign == serviceUID {
		foreign = 65534 // conventional nobody uid; chown works by number
	}
	if foreign == 0 || foreign == serviceUID || foreign == os.Geteuid() {
		t.Skip("no distinguishable foreign uid available")
	}
	directory := privateTempDir(t)

	accepted := []struct {
		label string
		uid   int
		gid   int
		mode  os.FileMode
	}{
		{"root-owned 0640 delivered configuration", 0, 0, 0640},
		{"root-owned 0644 delivery resource", 0, 0, 0644},
		{"service-owned 0600 resource", serviceUID, serviceUID, 0600},
	}
	for i, testCase := range accepted {
		info := ownerFixture(t, directory, i, testCase.uid, testCase.gid, testCase.mode)
		if !validationResourceOwned(info, true) {
			t.Fatalf("system scope refused legitimate %s (uid=%d mode=%o)", testCase.label, testCase.uid, testCase.mode)
		}
	}
	refused := []struct {
		label string
		uid   int
		gid   int
		mode  os.FileMode
	}{
		{"foreign owner", foreign, foreign, 0600},
		{"root-owned group-writable", 0, 0, 0660},
		{"root-owned other-writable", 0, 0, 0606},
		{"service-owned group-writable", serviceUID, serviceUID, 0660},
	}
	for i, testCase := range refused {
		info := ownerFixture(t, directory, len(accepted)+i, testCase.uid, testCase.gid, testCase.mode)
		if validationResourceOwned(info, true) {
			t.Fatalf("system scope accepted %s (uid=%d mode=%o)", testCase.label, testCase.uid, testCase.mode)
		}
	}
}

// TestLinuxValidationResourceOwnershipUser pins the strict user-scope
// contract with real files: only the acting account's own files, with no
// group/other access at all. A foreign ownership is asserted when staging
// one is possible (root).
func TestLinuxValidationResourceOwnershipUser(t *testing.T) {
	directory := privateTempDir(t)
	self := os.Geteuid()
	if info := ownerFixture(t, directory, 0, self, self, 0600); !validationResourceOwned(info, false) {
		t.Fatal("user scope refused own private file")
	}
	if info := ownerFixture(t, directory, 1, self, self, 0640); validationResourceOwned(info, false) {
		t.Fatal("user scope accepted group-readable own file")
	}
	if info := ownerFixture(t, directory, 2, self, self, 0660); validationResourceOwned(info, false) {
		t.Fatal("user scope accepted group-writable own file")
	}
	if os.Geteuid() != 0 {
		return // chown to any other uid requires root
	}
	if foreign := nobodyUID(); foreign > 0 {
		if info := ownerFixture(t, directory, 3, foreign, foreign, 0600); validationResourceOwned(info, false) {
			t.Fatal("user scope accepted foreign-owned file")
		}
	}
}
