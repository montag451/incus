package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lxc/incus/v6/internal/instance"
	"github.com/lxc/incus/v6/shared/api"
)

func (g *cmdGlobal) cmpGetRemote(s string) string {
	remote, _, found := strings.Cut(s, ":")
	if !found {
		return g.conf.DefaultRemote
	}

	return remote
}

func (g *cmdGlobal) appendCmp(comps []string, comp, toComplete string) []string {
	if !strings.HasPrefix(comp, toComplete) {
		return comps
	}

	return append(comps, comp)
}

func (g *cmdGlobal) appendCmpWithRemote(comps []string, comp, toComplete, remote string) []string {
	if remote != g.conf.DefaultRemote || strings.Contains(toComplete, g.conf.DefaultRemote) {
		comp = remote + ":" + comp
	}

	return g.appendCmp(comps, comp, toComplete)
}

func (g *cmdGlobal) appendCmpRemotes(comps []string, directives cobra.ShellCompDirective, toComplete string, includeAll bool) ([]string, cobra.ShellCompDirective) {
	if strings.Contains(toComplete, ":") {
		return comps, directives
	}

	remotes, rdirectives := g.cmpRemotes(toComplete, includeAll)
	return append(comps, remotes...), directives | rdirectives
}

func (g *cmdGlobal) cmpClusterGroupNames(toComplete string) ([]string, cobra.ShellCompDirective) {
	var results []string
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	cluster, _, err := resource.server.GetCluster()
	if err != nil || !cluster.Enabled {
		return nil, cobra.ShellCompDirectiveError
	}

	results, err = resource.server.GetClusterGroupNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpClusterGroups(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	cluster, _, err := resource.server.GetCluster()
	if err != nil || !cluster.Enabled {
		return nil, cobra.ShellCompDirectiveError
	}

	groups, err := resource.server.GetClusterGroupNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	for _, group := range groups {
		results = g.appendCmpWithRemote(results, group, toComplete, resource.remote)
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpClusterGroupConfigs(toComplete, groupName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(groupName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	cluster, _, err := client.GetCluster()
	if err != nil || !cluster.Enabled {
		return nil, cobra.ShellCompDirectiveError
	}

	group, _, err := client.GetClusterGroup(groupName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range group.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpClusterMemberConfigs(toComplete, memberName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(memberName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	cluster, _, err := client.GetCluster()
	if err != nil || !cluster.Enabled {
		return nil, cobra.ShellCompDirectiveError
	}

	member, _, err := client.GetClusterMember(memberName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range member.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpClusterMemberRoles(memberName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(memberName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	cluster, _, err := client.GetCluster()
	if err != nil || !cluster.Enabled {
		return nil, cobra.ShellCompDirectiveError
	}

	member, _, err := client.GetClusterMember(memberName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return member.Roles, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpClusterMembers(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		cluster, _, err := resource.server.GetCluster()
		if err != nil || !cluster.Enabled {
			return nil, cobra.ShellCompDirectiveError
		}

		// Get the cluster members
		members, err := resource.server.GetClusterMembers()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		for _, member := range members {
			results = g.appendCmpWithRemote(results, member.ServerName, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpImages(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	remote := g.cmpGetRemote(toComplete)
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	remoteServer, _ := g.conf.GetImageServer(remote)

	images, _ := remoteServer.GetImages()

	for _, image := range images {
		for _, alias := range image.Aliases {
			results = g.appendCmpWithRemote(results, alias.Name, toComplete, remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, true)
}

func (g *cmdGlobal) cmpImageFingerprints(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	remote := g.cmpGetRemote(toComplete)
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	remoteServer, _ := g.conf.GetImageServer(remote)

	images, _ := remoteServer.GetImages()

	for _, image := range images {
		results = g.appendCmpWithRemote(results, image.Fingerprint, toComplete, remote)
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, true)
}

func (g *cmdGlobal) cmpInstanceAllKeys(toComplete string) ([]string, cobra.ShellCompDirective) {
	keys := []string{}
	for k := range instance.InstanceConfigKeysAny {
		keys = g.appendCmp(keys, k, toComplete)
	}

	return keys, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpInstanceConfigTemplates(instanceName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(instanceName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	_, instanceNameOnly, found := strings.Cut(instanceName, ":")
	if !found {
		instanceNameOnly = instanceName
	}

	results, err := client.GetInstanceTemplateFiles(instanceNameOnly)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpInstanceDeviceNames(toComplete, instanceName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(instanceName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	instanceNameOnly, _, err := client.GetInstance(instanceName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range instanceNameOnly.Devices {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpInstanceSnapshots(instanceName string) ([]string, cobra.ShellCompDirective) {
	resources, err := g.ParseServers(instanceName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	snapshots, err := client.GetInstanceSnapshotNames(instanceName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return snapshots, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpInstances(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		instances, _ := resource.server.GetInstanceNames(api.InstanceTypeAny)
		for _, instName := range instances {
			results = g.appendCmpWithRemote(results, instName, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpInstancesAndSnapshots(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		if strings.Contains(resource.name, instance.SnapshotDelimiter) {
			instName, _, _ := strings.Cut(resource.name, instance.SnapshotDelimiter)
			snapshots, _ := resource.server.GetInstanceSnapshotNames(instName)
			for _, snapshot := range snapshots {
				results = g.appendCmp(results, instName+"/"+snapshot, toComplete)
			}
		} else {
			instances, _ := resource.server.GetInstanceNames(api.InstanceTypeAny)
			for _, instName := range instances {
				results = g.appendCmpWithRemote(results, instName, toComplete, resource.remote)
			}
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpInstanceNamesFromRemote(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]
		containers, _ := resource.server.GetInstanceNames("container")
		results = append(results, containers...)
		vms, _ := resource.server.GetInstanceNames("virtual-machine")
		results = append(results, vms...)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkACLConfigs(toComplete, aclName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(aclName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	acl, _, err := client.GetNetworkACL(resource.name)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range acl.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkACLs(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	acls, err := resource.server.GetNetworkACLNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	for _, acl := range acls {
		results = g.appendCmpWithRemote(results, acl, toComplete, resource.remote)
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpNetworkACLRuleProperties(toComplete string) ([]string, cobra.ShellCompDirective) {
	var results []string

	allowedKeys := networkACLRuleJSONStructFieldMap()
	for key := range allowedKeys {
		results = g.appendCmp(results, key+"=", toComplete)
	}

	return results, cobra.ShellCompDirectiveNoSpace
}

func (g *cmdGlobal) cmpNetworkForwardConfigs(toComplete, networkName, listenAddress string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(networkName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	forward, _, err := client.GetNetworkForward(networkName, listenAddress)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range forward.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkForwards(networkName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(networkName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	results, err := resource.server.GetNetworkForwardAddresses(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworkLoadBalancers(networkName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(networkName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	results, err := resource.server.GetNetworkForwardAddresses(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworkPeerConfigs(toComplete, networkName, peerName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(networkName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	peer, _, err := resource.server.GetNetworkPeer(resource.name, peerName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	for k := range peer.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworkPeers(networkName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(networkName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	results, err := resource.server.GetNetworkPeerNames(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworks(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		networks, err := resource.server.GetNetworkNames()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		for _, network := range networks {
			results = g.appendCmpWithRemote(results, network, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpNetworkConfigs(toComplete, networkName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(networkName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	network, _, err := client.GetNetwork(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range network.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkInstances(toComplete, networkName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(networkName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	network, _, err := client.GetNetwork(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for _, i := range network.UsedBy {
		r := regexp.MustCompile(`/1.0/instances/(.*)`)
		match := r.FindStringSubmatch(i)

		if len(match) == 2 {
			results = g.appendCmp(results, match[1], toComplete)
		}
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkProfiles(toComplete, networkName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(networkName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	network, _, err := client.GetNetwork(networkName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for _, i := range network.UsedBy {
		r := regexp.MustCompile(`/1.0/profiles/(.*)`)
		match := r.FindStringSubmatch(i)

		if len(match) == 2 {
			results = g.appendCmp(results, match[1], toComplete)
		}
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkZoneConfigs(toComplete, zoneName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(zoneName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	zone, _, err := client.GetNetworkZone(zoneName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range zone.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpNetworkZoneRecordConfigs(toComplete, zoneName, recordName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(zoneName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	peer, _, err := resource.server.GetNetworkZoneRecord(resource.name, recordName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	for k := range peer.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworkZoneRecords(zoneName string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(zoneName)

	if len(resources) <= 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]

	results, err := resource.server.GetNetworkZoneRecordNames(zoneName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return results, cmpDirectives
}

func (g *cmdGlobal) cmpNetworkZones(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		zones, err := resource.server.GetNetworkZoneNames()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		for _, project := range zones {
			results = g.appendCmpWithRemote(results, project, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpProfileConfigs(toComplete, profileName string) ([]string, cobra.ShellCompDirective) {
	resources, err := g.ParseServers(profileName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	profile, _, err := client.GetProfile(resource.name)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var configs []string
	for c := range profile.Config {
		configs = g.appendCmp(configs, c, toComplete)
	}

	return configs, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpProfileDeviceNames(toComplete, instanceName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(instanceName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	profile, _, err := client.GetProfile(resource.name)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range profile.Devices {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpProfileNamesFromRemote(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		profiles, _ := resource.server.GetProfileNames()
		results = append(results, profiles...)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpProfiles(toComplete string, includeRemotes bool) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		profiles, _ := resource.server.GetProfileNames()

		for _, profile := range profiles {
			results = g.appendCmpWithRemote(results, profile, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpProjectConfigs(toComplete, projectName string) ([]string, cobra.ShellCompDirective) {
	resources, err := g.ParseServers(projectName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	project, _, err := client.GetProject(resource.name)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var configs []string
	for c := range project.Config {
		configs = g.appendCmp(configs, c, toComplete)
	}

	return configs, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpProjects(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}
	cmpDirectives := cobra.ShellCompDirectiveNoFileComp

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		projects, err := resource.server.GetProjectNames()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		for _, project := range projects {
			results = g.appendCmpWithRemote(results, project, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cmpDirectives, toComplete, false)
}

func (g *cmdGlobal) cmpRemotes(toComplete string, includeAll bool) ([]string, cobra.ShellCompDirective) {
	results := []string{}

	for remoteName, rc := range g.conf.Remotes {
		if !includeAll && rc.Protocol != "incus" && rc.Protocol != "" {
			continue
		}

		results = g.appendCmp(results, remoteName+":", toComplete)
	}

	if len(results) > 0 {
		return results, cobra.ShellCompDirectiveNoSpace
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpRemoteNames(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}

	for remoteName := range g.conf.Remotes {
		results = g.appendCmp(results, remoteName, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolConfigs(toComplete, poolName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	pool, _, err := client.GetStoragePool(poolName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range pool.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolWithVolume(toComplete string) ([]string, cobra.ShellCompDirective) {
	if !strings.Contains(toComplete, "/") {
		pools, compdir := g.cmpStoragePools(toComplete)
		if compdir == cobra.ShellCompDirectiveError {
			return nil, compdir
		}

		results := []string{}
		for _, pool := range pools {
			if strings.HasSuffix(pool, ":") {
				results = append(results, pool)
			} else {
				results = append(results, pool+"/")
			}
		}

		return results, cobra.ShellCompDirectiveNoSpace
	}

	pool, _, _ := strings.Cut(toComplete, "/")
	volumes, compdir := g.cmpStoragePoolVolumes(pool)
	if compdir == cobra.ShellCompDirectiveError {
		return nil, compdir
	}

	results := []string{}
	for _, volume := range volumes {
		results = append(results, pool+"/"+volume)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePools(toComplete string) ([]string, cobra.ShellCompDirective) {
	results := []string{}

	resources, _ := g.ParseServers(toComplete)

	if len(resources) > 0 {
		resource := resources[0]

		storagePools, _ := resource.server.GetStoragePoolNames()

		for _, storage := range storagePools {
			results = g.appendCmpWithRemote(results, storage, toComplete, resource.remote)
		}
	}

	return g.appendCmpRemotes(results, cobra.ShellCompDirectiveNoFileComp, toComplete, false)
}

func (g *cmdGlobal) cmpStoragePoolVolumeConfigs(toComplete, poolName, volumeName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	volName, volType := parseVolume("custom", volumeName)

	volume, _, err := client.GetStoragePoolVolume(poolName, volType, volName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for k := range volume.Config {
		results = g.appendCmp(results, k, toComplete)
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolVolumeInstances(toComplete, poolName, volumeName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	volName, volType := parseVolume("custom", volumeName)

	volume, _, err := client.GetStoragePoolVolume(poolName, volType, volName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for _, i := range volume.UsedBy {
		r := regexp.MustCompile(`/1.0/instances/(.*)`)
		match := r.FindStringSubmatch(i)

		if len(match) == 2 {
			results = g.appendCmp(results, match[1], toComplete)
		}
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolVolumeProfiles(toComplete, poolName, volumeName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	volName, volType := parseVolume("custom", volumeName)

	volume, _, err := client.GetStoragePoolVolume(poolName, volType, volName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for _, i := range volume.UsedBy {
		r := regexp.MustCompile(`/1.0/profiles/(.*)`)
		match := r.FindStringSubmatch(i)

		if len(match) == 2 {
			results = g.appendCmp(results, match[1], toComplete)
		}
	}

	return results, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolVolumeSnapshots(poolName string, volumeName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	volName, volType := parseVolume("custom", volumeName)

	snapshots, err := client.GetStoragePoolVolumeSnapshotNames(poolName, volType, volName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return snapshots, cobra.ShellCompDirectiveNoFileComp
}

func (g *cmdGlobal) cmpStoragePoolVolumes(poolName string) ([]string, cobra.ShellCompDirective) {
	// Parse remote
	resources, err := g.ParseServers(poolName)
	if err != nil || len(resources) == 0 {
		return nil, cobra.ShellCompDirectiveError
	}

	resource := resources[0]
	client := resource.server

	if strings.Contains(poolName, ":") {
		_, poolName, _ = strings.Cut(poolName, ":")
	}

	volumes, err := client.GetStoragePoolVolumeNames(poolName)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	return volumes, cobra.ShellCompDirectiveNoFileComp
}

func isSymlinkToDir(path string, d fs.DirEntry) bool {
	if d.Type()&fs.ModeSymlink == 0 {
		return false
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	return true
}

func (g *cmdGlobal) cmpFiles(toComplete string, includeLocalFiles bool) ([]string, cobra.ShellCompDirective) {
	instances, directives := g.cmpInstances(toComplete)
	for i := range instances {
		if strings.HasSuffix(instances[i], ":") {
			continue
		}

		instances[i] += "/"
	}

	if len(instances) == 0 {
		if includeLocalFiles {
			return nil, cobra.ShellCompDirectiveDefault
		}

		return instances, directives
	}

	directives |= cobra.ShellCompDirectiveNoSpace

	if !includeLocalFiles {
		return instances, directives
	}

	var files []string
	sep := string(filepath.Separator)
	dir, prefix := filepath.Split(toComplete)
	switch prefix {
	case ".":
		files = append(files, dir+"."+sep)
		fallthrough
	case "..":
		files = append(files, dir+".."+sep)
		directives |= cobra.ShellCompDirectiveNoSpace
	}

	root, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		return append(instances, files...), directives
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}

		base := filepath.Base(path)
		if strings.HasPrefix(base, prefix) {
			file := dir + base
			switch {
			case d.IsDir():
				directives |= cobra.ShellCompDirectiveNoSpace
				file += sep
			case isSymlinkToDir(path, d):
				directives |= cobra.ShellCompDirectiveNoSpace
				if base == prefix {
					file += sep
				}
			}

			files = append(files, file)
		}

		if d.IsDir() {
			return fs.SkipDir
		}

		return nil
	})

	return append(instances, files...), directives
}
