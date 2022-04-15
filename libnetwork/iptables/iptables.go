//go:build linux
// +build linux

package iptables

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/libnetwork/firewallapi"
	"github.com/docker/docker/libnetwork/firewalld"
	"github.com/sirupsen/logrus"
)

// Action signifies the nftable action.
type Action = firewallapi.Action

// Policy is the default nftable policies
type Policy = firewallapi.Policy

// Table refers to Nat, Filter or Mangle.
type Table = firewallapi.Table

// IPVersion refers to IP version, v4 or v6
type IPVersion = firewallapi.IPVersion

const (
	// Append appends the rule at the end of the chain.
	Append Action = "-A"
	// Delete deletes the rule from the chain.
	Delete Action = "-D"
	// Insert inserts the rule at the top of the chain.
	Insert Action = "-I"
	// Nat table is used for nat translation rules.
	Nat firewallapi.Table = firewallapi.Nat
	// Filter table is used for filter rules.
	Filter firewallapi.Table = firewallapi.Filter
	// Mangle table is used for mangling the packet.
	Mangle firewallapi.Table = firewallapi.Mangle
	// Drop is the default iptables DROP policy
	Drop Policy = "DROP"
	// Accept is the default iptables ACCEPT policy
	Accept Policy = "ACCEPT"
	// IPv4 is version 4
	IPv4 IPVersion = "IPV4"
	// IPv6 is version 6
	IPv6 IPVersion = "IPV6"
)

var (
	iptablesPath  string
	ip6tablesPath string
	supportsXlock = false
	supportsCOpt  = false
	xLockWaitMsg  = "Another app is currently holding the xtables lock"
	// used to lock iptables commands if xtables lock is not supported
	bestEffortLock sync.Mutex
	// ErrIptablesNotFound is returned when the rule is not found.
	ErrIptablesNotFound = errors.New("Iptables not found")
	initOnce            sync.Once
)

// IPTable defines struct with IPVersion
type IPTable struct {
	firewallapi.FirewallTable
	Version IPVersion
}

// ChainInfo defines the iptables chain.
type ChainInfo struct {
	Name          string
	Table         Table
	HairpinMode   bool
	FirewallTable IPTable
}

// ChainError is returned to represent errors during ip table operation.
type ChainError struct {
	Chain  string
	Output []byte
}

func (e ChainError) Error() string {
	return fmt.Sprintf("Error iptables %s: %s", e.Chain, string(e.Output))
}

func probe() {
	path, err := exec.LookPath("iptables")
	if err != nil {
		logrus.Warnf("Failed to find iptables: %v", err)
		return
	}
	if out, err := exec.Command(path, "--wait", "-t", "nat", "-L", "-n").CombinedOutput(); err != nil {
		logrus.Warnf("Running iptables --wait -t nat -L -n failed with message: `%s`, error: %v", strings.TrimSpace(string(out)), err)
	}
	_, err = exec.LookPath("ip6tables")
	if err != nil {
		logrus.Warnf("Failed to find ip6tables: %v", err)
		return
	}
}

func initFirewalld() {
	if err := firewalld.FirewalldInit(); err != nil {
		logrus.Debugf("Fail to initialize firewalld: %v, using raw iptables instead", err)
	}
}

func detectIptables() {
	path, err := exec.LookPath("iptables")
	if err != nil {
		return
	}
	iptablesPath = path
	path, err = exec.LookPath("ip6tables")
	if err != nil {
		return
	}
	ip6tablesPath = path
	supportsXlock = exec.Command(iptablesPath, "--wait", "-L", "-n").Run() == nil
	mj, mn, mc, err := GetVersion()
	if err != nil {
		logrus.Warnf("Failed to read iptables version: %v", err)
		return
	}
	supportsCOpt = supportsCOption(mj, mn, mc)
}

func initDependencies() {
	probe()
	initFirewalld()
	detectIptables()
}

func InitCheck() error {
	initOnce.Do(initDependencies)

	if iptablesPath == "" {
		return ErrIptablesNotFound
	}
	return nil
}

// GetTable returns an instance of IPTable with specified version
func GetTable(version IPVersion) *IPTable {
	return &IPTable{Version: version}
}

// NewChain adds a new chain to ip table.
func (iptable IPTable) NewChain(name string, table Table, hairpinMode bool) (firewallapi.FirewallChain, error) {
	c := &ChainInfo{
		Name:          name,
		Table:         table,
		HairpinMode:   hairpinMode,
		FirewallTable: iptable,
	}
	if string(c.GetTable()) == "" {
		c.Table = Filter
	}

	// Add chain if it doesn't exist
	if _, err := iptable.Raw("-t", string(c.GetTable()), "-n", "-L", c.GetName()); err != nil {
		if output, err := iptable.Raw("-t", string(c.GetTable()), "-N", c.GetName()); err != nil {
			return nil, err
		} else if len(output) != 0 {
			return nil, fmt.Errorf("Could not create %s/%s chain: %s", c.GetTable(), c.GetName(), output)
		}
	}
	return c, nil
}

func (iptable IPTable) FlushChain(table Table, name string) error {
	if _, err := iptable.Raw("-t", string(table), "-F"); err != nil {
		return err
	}

	return nil
}

// LoopbackByVersion returns loopback address by version
func (iptable IPTable) LoopbackByVersion() string {
	if iptable.Version == IPv6 {
		return "::1/128"
	}
	return "127.0.0.0/8"
}

// ProgramChain is used to add rules to a chain
func (iptable IPTable) ProgramChain(c firewallapi.FirewallChain, bridgeName string, hairpinMode, enable bool) error {
	if c.GetName() == "" {
		return errors.New("Could not program chain, missing chain name")
	}

	// Either add or remove the interface from the firewalld zone
	if firewalld.FirewalldRunning {
		if enable {
			if err := firewalld.AddInterfaceFirewalld(bridgeName); err != nil {
				return err
			}
		} else {
			if err := firewalld.DelInterfaceFirewalld(bridgeName); err != nil {
				return err
			}
		}
	}

	switch c.GetTable() {
	case Nat:
		preroute := []string{
			"-m", "addrtype",
			"--dst-type", "LOCAL",
			"-j", c.GetName()}
		if !iptable.Exists(Nat, "PREROUTING", preroute...) && enable {
			if err := c.Prerouting(Append, preroute...); err != nil {
				return fmt.Errorf("Failed to inject %s in PREROUTING chain: %s", c.GetName(), err)
			}
		} else if iptable.Exists(Nat, "PREROUTING", preroute...) && !enable {
			if err := c.Prerouting(Delete, preroute...); err != nil {
				return fmt.Errorf("Failed to remove %s in PREROUTING chain: %s", c.GetName(), err)
			}
		}
		output := []string{
			"-m", "addrtype",
			"--dst-type", "LOCAL",
			"-j", c.GetName()}
		if !hairpinMode {
			output = append(output, "!", "--dst", iptable.LoopbackByVersion())
		}
		if !iptable.Exists(Nat, "OUTPUT", output...) && enable {
			if err := c.Output(Append, output...); err != nil {
				return fmt.Errorf("Failed to inject %s in OUTPUT chain: %s", c.GetName(), err)
			}
		} else if iptable.Exists(Nat, "OUTPUT", output...) && !enable {
			if err := c.Output(Delete, output...); err != nil {
				return fmt.Errorf("Failed to inject %s in OUTPUT chain: %s", c.GetName(), err)
			}
		}
	case Filter:
		if bridgeName == "" {
			return fmt.Errorf("Could not program chain %s/%s, missing bridge name",
				c.GetTable(), c.GetName())
		}
		link := []string{
			"-o", bridgeName,
			"-j", c.GetName()}
		if !iptable.Exists(Filter, "FORWARD", link...) && enable {
			insert := append([]string{string(Insert), "FORWARD"}, link...)
			if output, err := iptable.Raw(insert...); err != nil {
				return err
			} else if len(output) != 0 {
				return fmt.Errorf("Could not create linking rule to %s/%s: %s", c.GetTable(), c.GetName(), output)
			}
		} else if iptable.Exists(Filter, "FORWARD", link...) && !enable {
			del := append([]string{string(Delete), "FORWARD"}, link...)
			if output, err := iptable.Raw(del...); err != nil {
				return err
			} else if len(output) != 0 {
				return fmt.Errorf("Could not delete linking rule from %s/%s: %s", c.GetTable(), c.GetName(), output)
			}

		}
		establish := []string{
			"-o", bridgeName,
			"-m", "conntrack",
			"--ctstate", "RELATED,ESTABLISHED",
			"-j", "ACCEPT"}
		if !iptable.Exists(Filter, "FORWARD", establish...) && enable {
			insert := append([]string{string(Insert), "FORWARD"}, establish...)
			if output, err := iptable.Raw(insert...); err != nil {
				return err
			} else if len(output) != 0 {
				return fmt.Errorf("Could not create establish rule to %s: %s", c.GetTable(), output)
			}
		} else if iptable.Exists(Filter, "FORWARD", establish...) && !enable {
			del := append([]string{string(Delete), "FORWARD"}, establish...)
			if output, err := iptable.Raw(del...); err != nil {
				return err
			} else if len(output) != 0 {
				return fmt.Errorf("Could not delete establish rule from %s: %s", c.GetTable(), output)
			}
		}
	}
	return nil
}

// RemoveExistingChain removes existing chain from the table.
func (iptable IPTable) RemoveExistingChain(name string, table Table) error {
	c := &ChainInfo{
		Name:          name,
		Table:         table,
		FirewallTable: iptable,
	}
	if string(c.GetTable()) == "" {
		c.Table = Filter
	}
	return c.Remove()
}

func (c ChainInfo) DeleteRule(version IPVersion, table Table, chain string, rule ...string) error {
	iptable := GetTable(version)
	del := append([]string{"-t", string(table), string(Delete), chain}, rule...)
	if output, err := iptable.Raw(del...); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Could not delete establish rule from %s: %s", c.GetTable(), output)
	}
	return nil
}

//DeleteRule passes down to a raw level since it's more complex in NFTables
func (iptable IPTable) DeleteRule(version IPVersion, table Table, chain string, rule ...string) error {
	del := append([]string{"-t", string(table), string(Delete), chain}, rule...)
	if output, err := iptable.Raw(del...); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Could not delete establish rule from %s: %s", iptable.Version, output)
	}
	return nil
}

// Forward adds forwarding rule to 'filter' table and corresponding nat rule to 'nat' table.
func (c ChainInfo) Forward(action Action, ip net.IP, port int, proto, destAddr string, destPort int, bridgeName string) error {

	iptable := GetTable(c.FirewallTable.Version)
	daddr := ip.String()
	if ip.IsUnspecified() {
		// iptables interprets "0.0.0.0" as "0.0.0.0/32", whereas we
		// want "0.0.0.0/0". "0/0" is correctly interpreted as "any
		// value" by both iptables and ip6tables.
		daddr = "0/0"
	}

	args := []string{
		"-p", proto,
		"-d", daddr,
		"--dport", strconv.Itoa(port),
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(destAddr, strconv.Itoa(destPort))}

	if !c.HairpinMode {
		args = append(args, "!", "-i", bridgeName)
	}
	if err := iptable.ProgramRule(Nat, c.GetName(), action, args); err != nil {
		return err
	}

	args = []string{
		"!", "-i", bridgeName,
		"-o", bridgeName,
		"-p", proto,
		"-d", destAddr,
		"--dport", strconv.Itoa(destPort),
		"-j", "ACCEPT",
	}
	if err := iptable.ProgramRule(Filter, c.GetName(), action, args); err != nil {
		return err
	}

	args = []string{
		"-p", proto,
		"-s", destAddr,
		"-d", destAddr,
		"--dport", strconv.Itoa(destPort),
		"-j", "MASQUERADE",
	}

	if err := iptable.ProgramRule(Nat, "POSTROUTING", action, args); err != nil {
		return err
	}

	if proto == "sctp" {
		// Linux kernel v4.9 and below enables NETIF_F_SCTP_CRC for veth by
		// the following commit.
		// This introduces a problem when conbined with a physical NIC without
		// NETIF_F_SCTP_CRC. As for a workaround, here we add an iptables entry
		// to fill the checksum.
		//
		// https://github.com/torvalds/linux/commit/c80fafbbb59ef9924962f83aac85531039395b18
		args = []string{
			"-p", proto,
			"--sport", strconv.Itoa(destPort),
			"-j", "CHECKSUM",
			"--checksum-fill",
		}
		if err := iptable.ProgramRule(Mangle, "POSTROUTING", action, args); err != nil {
			return err
		}
	}

	return nil
}

// Link adds reciprocal ACCEPT rule for two supplied IP addresses.
// Traffic is allowed from ip1 to ip2 and vice-versa
func (c ChainInfo) Link(action Action, ip1, ip2 net.IP, port int, proto string, bridgeName string) error {
	iptable := GetTable(c.FirewallTable.Version)
	// forward
	args := []string{
		"-i", bridgeName, "-o", bridgeName,
		"-p", proto,
		"-s", ip1.String(),
		"-d", ip2.String(),
		"--dport", strconv.Itoa(port),
		"-j", "ACCEPT",
	}

	if err := iptable.ProgramRule(Filter, c.GetName(), action, args); err != nil {
		return err
	}
	// reverse
	args[7], args[9] = args[9], args[7]
	args[10] = "--sport"
	return iptable.ProgramRule(Filter, c.GetName(), action, args)
}

// ProgramRule adds the rule specified by args only if the
// rule is not already present in the chain. Reciprocally,
// it removes the rule only if present.
func (iptable IPTable) ProgramRule(table Table, chain string, action Action, args []string) error {
	if iptable.Exists(table, chain, args...) != (action == Delete) {
		return nil
	}
	return iptable.RawCombinedOutput(append([]string{"-t", string(table), string(action), chain}, args...)...)
}

// Prerouting adds linking rule to nat/PREROUTING chain.
func (c ChainInfo) Prerouting(action Action, args ...string) error {
	iptable := GetTable(c.FirewallTable.Version)
	a := []string{"-t", string(Nat), string(action), "PREROUTING"}
	if len(args) > 0 {
		a = append(a, args...)
	}
	if output, err := iptable.Raw(a...); err != nil {
		return err
	} else if len(output) != 0 {
		return ChainError{Chain: "PREROUTING", Output: output}
	}
	return nil

}

// Forward adds linking rule to forward chain.
func (c ChainInfo) ForwardChain(action Action, args ...string) error {
	iptable := GetTable(c.FirewallTable.Version)
	a := []string{"-t", string(Nat), string(action), "FORWARD"}
	if len(args) > 0 {
		a = append(a, args...)
	}
	if output, err := iptable.Raw(a...); err != nil {
		return err
	} else if len(output) != 0 {
		return ChainError{Chain: "FORWARD", Output: output}
	}
	return nil
}

// Output adds linking rule to an OUTPUT chain.
func (c ChainInfo) Output(action Action, args ...string) error {
	iptable := GetTable(c.FirewallTable.Version)
	a := []string{"-t", string(c.GetTable()), string(action), "OUTPUT"}
	if len(args) > 0 {
		a = append(a, args...)
	}
	if output, err := iptable.Raw(a...); err != nil {
		return err
	} else if len(output) != 0 {
		return ChainError{Chain: "OUTPUT", Output: output}
	}
	return nil
}

// Remove removes the chain.
func (c ChainInfo) Remove() error {
	iptable := GetTable(c.FirewallTable.Version)
	// Ignore errors - This could mean the chains were never set up
	if c.GetTable() == Nat {
		c.Prerouting(Delete, "-m", "addrtype", "--dst-type", "LOCAL", "-j", c.GetName())
		c.Output(Delete, "-m", "addrtype", "--dst-type", "LOCAL", "!", "--dst", iptable.LoopbackByVersion(), "-j", c.GetName())
		c.Output(Delete, "-m", "addrtype", "--dst-type", "LOCAL", "-j", c.GetName()) // Created in versions <= 0.16.6

		c.Prerouting(Delete)
		c.Output(Delete)
	}
	iptable.Raw("-t", string(c.GetTable()), "-F", c.GetName())
	iptable.Raw("-t", string(c.GetTable()), "-X", c.GetName())
	return nil
}

// Exists checks if a rule exists
func (iptable IPTable) Exists(table Table, chain string, rule ...string) bool {
	return iptable.exists(false, table, chain, rule...)
}

// ExistsNative behaves as Exists with the difference it
// will always invoke `iptables` binary.
func (iptable IPTable) ExistsNative(table Table, chain string, rule ...string) bool {
	return iptable.exists(true, table, chain, rule...)
}

func (iptable IPTable) exists(native bool, table Table, chain string, rule ...string) bool {
	f := iptable.Raw
	if native {
		f = iptable.raw
	}

	if string(table) == "" {
		table = Filter
	}

	if err := InitCheck(); err != nil {
		// The exists() signature does not allow us to return an error, but at least
		// we can skip the (likely invalid) exec invocation.
		return false
	}

	if supportsCOpt {
		// if exit status is 0 then return true, the rule exists
		_, err := f(append([]string{"-t", string(table), "-C", chain}, rule...)...)
		return err == nil
	}

	// parse "iptables -S" for the rule (it checks rules in a specific chain
	// in a specific table and it is very unreliable)
	return iptable.existsRaw(table, chain, rule...)
}

func (iptable IPTable) existsRaw(table Table, chain string, rule ...string) bool {
	path := iptablesPath
	if iptable.Version == IPv6 {
		path = ip6tablesPath
	}
	ruleString := fmt.Sprintf("%s %s\n", chain, strings.Join(rule, " "))
	existingRules, _ := exec.Command(path, "-t", string(table), "-S", chain).Output()

	return strings.Contains(string(existingRules), ruleString)
}

// Maximum duration that an iptables operation can take
// before flagging a warning.
const opWarnTime = 2 * time.Second

func filterOutput(start time.Time, output []byte, args ...string) []byte {
	// Flag operations that have taken a long time to complete
	opTime := time.Since(start)
	if opTime > opWarnTime {
		logrus.Warnf("xtables contention detected while running [%s]: Waited for %.2f seconds and received %q", strings.Join(args, " "), float64(opTime)/float64(time.Second), string(output))
	}
	// ignore iptables' message about xtables lock:
	// it is a warning, not an error.
	if strings.Contains(string(output), xLockWaitMsg) {
		output = []byte("")
	}
	// Put further filters here if desired
	return output
}

// Raw calls 'iptables' system command, passing supplied arguments.
func (iptable IPTable) Raw(args ...string) ([]byte, error) {
	if firewalld.FirewalldRunning {
		startTime := time.Now()
		output, err := firewalld.Passthrough(firewalld.Iptables, args...)
		if err == nil || !strings.Contains(err.Error(), "was not provided by any .service files") {
			return filterOutput(startTime, output, args...), err
		}
	}
	return iptable.raw(args...)
}

func (iptable IPTable) raw(args ...string) ([]byte, error) {
	if err := InitCheck(); err != nil {
		return nil, err
	}
	if supportsXlock {
		args = append([]string{"--wait"}, args...)
	} else {
		bestEffortLock.Lock()
		defer bestEffortLock.Unlock()
	}

	path := iptablesPath
	commandName := "iptables"
	if iptable.Version == IPv6 {
		path = ip6tablesPath
		commandName = "ip6tables"
	}

	logrus.Debugf("%s, %v", path, args)

	startTime := time.Now()
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables failed: %s %v: %s (%s)", commandName, strings.Join(args, " "), output, err)
	}

	return filterOutput(startTime, output, args...), err
}

// RawCombinedOutput internally calls the Raw function and returns a non nil
// error if Raw returned a non nil error or a non empty output
func (iptable IPTable) RawCombinedOutput(args ...string) error {
	if output, err := iptable.Raw(args...); err != nil || len(output) != 0 {
		return fmt.Errorf("%s (%v)", string(output), err)
	}
	return nil
}

// RawCombinedOutputNative behave as RawCombinedOutput with the difference it
// will always invoke `iptables` binary
func (iptable IPTable) RawCombinedOutputNative(args ...string) error {
	if output, err := iptable.raw(args...); err != nil || len(output) != 0 {
		return fmt.Errorf("%s (%v)", string(output), err)
	}
	return nil
}

// ExistChain checks if a chain exists
func (iptable IPTable) ExistChain(chain string, table Table) bool {
	if _, err := iptable.Raw("-t", string(table), "-nL", chain); err == nil {
		return true
	}
	return false
}

// GetVersion reads the iptables version numbers during initialization
func GetVersion() (major, minor, micro int, err error) {
	out, err := exec.Command(iptablesPath, "--version").CombinedOutput()
	if err == nil {
		major, minor, micro = parseVersionNumbers(string(out))
	}
	return
}

// SetDefaultPolicy sets the passed default policy for the table/chain
func (iptable IPTable) SetDefaultPolicy(table Table, chain string, policy Policy) error {
	if err := iptable.RawCombinedOutput("-t", string(table), "-P", chain, string(policy)); err != nil {
		return fmt.Errorf("setting default policy to %v in %v chain failed: %v", policy, chain, err)
	}
	return nil
}

func parseVersionNumbers(input string) (major, minor, micro int) {
	re := regexp.MustCompile(`v\d*.\d*.\d*`)
	line := re.FindString(input)
	fmt.Sscanf(line, "v%d.%d.%d", &major, &minor, &micro)
	return
}

// iptables -C, --check option was added in v.1.4.11
// http://ftp.netfilter.org/pub/iptables/changes-iptables-1.4.11.txt
func supportsCOption(mj, mn, mc int) bool {
	return mj > 1 || (mj == 1 && (mn > 4 || (mn == 4 && mc >= 11)))
}

// AddReturnRule adds a return rule for the chain in the filter table
func (iptable IPTable) AddReturnRule(chain string) error {
	var (
		table = Filter
		args  = []string{"-j", "RETURN"}
	)

	if iptable.Exists(table, chain, args...) {
		return nil
	}

	err := iptable.RawCombinedOutput(append([]string{"-A", chain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to add return rule in %s chain: %s", chain, err.Error())
	}

	return nil
}

// EnsureJumpRule ensures the jump rule is on top
func (iptable IPTable) EnsureJumpRule(fromChain, toChain string) error {
	var (
		table = Filter
		args  = []string{"-j", toChain}
	)

	if iptable.Exists(table, fromChain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", fromChain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove jump to %s rule in %s chain: %s", toChain, fromChain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-I", fromChain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert jump to %s rule in %s chain: %s", toChain, fromChain, err.Error())
	}

	return nil
}

func (iptable IPTable) EnsureAcceptRule(chain string) error {
	var (
		table = Filter
		args  = []string{"-j", "ACCEPT"}
	)

	if iptable.Exists(table, chain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", chain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove accept rule in %s chain: %s", chain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-A", chain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert accept rule in %s chain: %s", chain, err.Error())
	}

	return nil
}

func (iptable IPTable) EnsureAcceptRuleForIface(chain, iface string) error {
	var (
		table = Filter
		args  = []string{"-o", iface, "-j", "ACCEPT"}
	)

	if iptable.Exists(table, chain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", chain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove accept rule in %s chain: %s", chain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-A", chain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert accept rule in %s chain: %s", chain, err.Error())
	}

	return nil
}

// EnsureJumpRule ensures the jump rule is on top
func (iptable IPTable) EnsureDropRule(chain string) error {
	var (
		table = Filter
		args  = []string{"-j", "DROP"}
	)

	if iptable.Exists(table, chain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", chain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove drop rule in %s chain: %s", chain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-A", chain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert drop rule in %s chain: %s", chain, err.Error())
	}

	return nil
}

// EnsureReturnRule ensures the jump rule is on top
func (iptable IPTable) EnsureReturnRule(table Table, chain string) error {
	var (
		args = []string{"-j", "RETURN"}
	)

	if !iptable.Exists(table, chain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-t", string(table), "-A", chain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to ensure return rule in %s chain: %s", chain, err.Error())
		}
	}

	return nil
}

// EnsureLocalMasquerade ensures the jump rule is on top
func (iptable IPTable) EnsureLocalMasquerade(table Table, fromChain, toChain string) error {
	var (
		args = []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", toChain}
	)

	if !iptable.Exists(table, fromChain, args...) {
		if err := iptable.RawCombinedOutput("-t", string(table), "-I", fromChain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", toChain); err != nil {
			return fmt.Errorf("failed to add jump rule in %s to ingress chain: %v", toChain, err)
		}
	}

	return nil
}

// EnsureLocalMasqueradeForIface ensures the jump rule is on top
func (iptable IPTable) EnsureLocalMasqueradeForIface(table Table, iface string) error {
	var (
		args = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", iface, "-j", "MASQUERADE"}
	)

	if !iptable.Exists(table, "POSTROUTING", args...) {
		if err := iptable.RawCombinedOutput(append([]string{"-t", "nat", "-I", "POSTROUTING"}, args...)...); err != nil {
			return fmt.Errorf("failed to add ingress localhost POSTROUTING rule for %s: %v", iface, err)
		}
	}

	return nil
}

func (iptable IPTable) EnsureDropRuleForIface(chain, iface string) error {
	var (
		table = Filter
		args  = []string{"-o", iface, "-j", "DROP"}
	)

	if iptable.Exists(table, chain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", chain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove drop rule in %s chain: %s", chain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-A", chain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert drop rule in %s chain: %s", chain, err.Error())
	}

	return nil
}

// EnsureJumpRule ensures the jump rule is on top
func (iptable IPTable) EnsureJumpRuleForIface(fromChain, toChain, iface string) error {
	var (
		table = Filter
		args  = []string{"-o", iface, "-j", toChain}
	)

	if iptable.Exists(table, fromChain, args...) {
		err := iptable.RawCombinedOutput(append([]string{"-D", fromChain}, args...)...)
		if err != nil {
			return fmt.Errorf("unable to remove jump to %s rule in %s chain: %s", toChain, fromChain, err.Error())
		}
	}

	err := iptable.RawCombinedOutput(append([]string{"-I", fromChain}, args...)...)
	if err != nil {
		return fmt.Errorf("unable to insert jump to %s rule in %s chain: %s", toChain, fromChain, err.Error())
	}

	return nil
}

//AddJumpRuleForIP ensures that there is a jump rule for a given IP at the top of the chain
func (iptable IPTable) AddJumpRuleForIP(table Table, fromChain, toChain, ipaddr string) {
	err := iptable.RawCombinedOutputNative("-t", string(table), "-C", fromChain, "-d", ipaddr, "-j", toChain)
	if err == nil {
		iptable.RawCombinedOutputNative("-t", string(table), "-F", toChain)
	} else {
		iptable.RawCombinedOutputNative("-t", string(table), "-N", toChain)
		iptable.RawCombinedOutputNative("-t", string(table), "-I", fromChain, "-d", ipaddr, "-j", toChain)
	}
}

//AddDNAT adds a dnat rule with a port
func (iptable IPTable) AddDNATwithPort(table Table, chain, dstIP, dstPort, proto, natIP string) {
	rule := []string{"-t", string(table), "-I", chain, "-d", dstIP, "-p", proto, "--dport", dstPort, "-j", "DNAT", "--to-destination", natIP}

	if err := iptable.RawCombinedOutputNative(rule...); err != nil {
		logrus.Errorf("set up rule failed: %v", err)
	}
}

//AddRedirect adds a redirect rule with a port
func (iptable IPTable) AddRedirect(table Table, chain, dstIP, dstPort, proto, natIP string) {
	rule := []string{"-t", string(table), "-d", dstIP, "-p", proto, "--dport", dstPort, "-j", "REDIRECT", "--to-destination", natIP}

	if iptable.RawCombinedOutputNative(rule...) != nil {
		logrus.Errorf("set up rule failed, %v", rule)
	}
}

//AddSNAT adds a snat rule with a port
func (iptable IPTable) ADDSNATwithPort(table Table, chain, srcIP, srcPort, proto, natPort string) {
	rule := []string{"-t", string(table), "-I", chain, "-s", srcIP, "-p", proto, "--sport", srcPort, "-j", "SNAT", "--to-source", ":" + natPort}

	if err := iptable.RawCombinedOutputNative(rule...); err != nil {
		logrus.Errorf("set up rule failed: %v", err)
	}
}

//AddDropIncoming
func (iptable IPTable) DropIncoming(table Table, chain, iface, addr string) error {
	rule := []string{"-t", string(table), "-i", iface, "!", "-d", addr, "-j", "DROP"}
	err := iptable.RawCombinedOutputNative(rule...)

	if err != nil {
		logrus.Errorf("set up rule failed, %v", rule)
	}
	return err
}

//AddDropOutgoing
func (iptable IPTable) DropOutgoing(table Table, chain, iface, addr string) error {
	rule := []string{"-t", string(table), "-o", iface, "!", "-s", addr, "-j", "DROP"}
	err := iptable.RawCombinedOutputNative(rule...)

	if err != nil {
		logrus.Errorf("set up rule failed, %v", rule)
	}
	return err
}

func (iptable IPTable) GetInsertAction() string {
	return string(Insert)
}

func (iptable IPTable) GetAppendAction() string {
	return string(Append)
}

func (iptable IPTable) GetDeleteAction() string {
	return string(Delete)
}

func (iptable IPTable) GetDropPolicy() string {
	return string(Drop)
}

func (iptable IPTable) GetAcceptPolicy() string {
	return string(Accept)
}

//Getters and setters for struct fields now that it's an interface
func (c ChainInfo) GetName() string {
	return c.Name
}

func (c ChainInfo) GetTable() Table {
	return c.Table
}

func (c ChainInfo) GetHairpinMode() bool {
	return c.HairpinMode
}

func (c ChainInfo) GetFirewallTable() firewallapi.FirewallTable {
	return c.FirewallTable
}
