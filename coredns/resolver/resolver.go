/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resolver

import (
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/client-go/dynamic"
	k8snet "k8s.io/utils/net"
)

func New(clusterStatus ClusterStatus, client dynamic.Interface) *Interface {
	return &Interface{
		clusterStatus: clusterStatus,
		serviceMap:    make(map[string]*serviceInfo),
		client:        client,
	}
}

func (i *Interface) GetDNSRecords(namespace, name, clusterID, hostname string, ipFamily k8snet.IPFamily) ([]DNSRecord, bool, bool) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	logger.Infof("GetDNSRecords called: namespace=%s, name=%s, clusterID=%s, hostname=%s, ipFamily=%v", namespace, name, clusterID, hostname, ipFamily)

	serviceInfo, found := i.serviceMap[keyFunc(namespace, name)]
	if !found {
		logger.Infof("Service not found in serviceMap")
		return nil, false, false
	}

	logger.Infof("Service found, isHeadless=%v, ipv4Info.clusters=%v, ipv6Info.clusters=%v",
		serviceInfo.isHeadless(), len(serviceInfo.ipv4Info.clusters), len(serviceInfo.ipv6Info.clusters))

	if serviceInfo.isHeadless() {
		records, found := i.getHeadlessRecords(serviceInfo, ipFamily, clusterID, hostname)

		logger.Infof("getHeadlessRecords returned %d records, found=%v", len(records), found)
		return records, true, found
	}

	var record *DNSRecord

	if ipFamily == k8snet.IPv4 {
		record, found = i.getClusterIPRecord(serviceInfo, discovery.AddressTypeIPv4, clusterID)
	} else if ipFamily == k8snet.IPv6 {
		record, found = i.getClusterIPRecord(serviceInfo, discovery.AddressTypeIPv6, clusterID)
	} else {
		for _, addrType := range []discovery.AddressType{discovery.AddressTypeIPv4, discovery.AddressTypeIPv6} {
			record, found = i.getClusterIPRecord(serviceInfo, addrType, clusterID)
			if record != nil {
				break
			}
		}
	}

	if record != nil {
		return []DNSRecord{*record}, false, true
	}

	return nil, false, found
}

func (i *Interface) getClusterIPRecord(serviceInfo *serviceInfo, addrType discovery.AddressType, clusterID string) (*DNSRecord, bool) {
	ipFamilyInfo := serviceInfo.getIPFamilyInfo(addrType)

	// If a clusterID is specified, we supply it even if the service is not healthy.
	if clusterID != "" {
		clusterInfo, found := ipFamilyInfo.clusters[clusterID]
		if !found {
			return nil, false
		}

		return &clusterInfo.endpointRecords[0], true
	}

	if len(serviceInfo.spec.IPs) > 0 {
		return &DNSRecord{
			IP:    serviceInfo.spec.IPs[0],
			Ports: serviceInfo.spec.Ports,
		}, true
	}

	// If we are aware of the local cluster and we found some accessible IP, we shall return it.
	localClusterID := i.clusterStatus.GetLocalClusterID()
	if localClusterID != "" {
		clusterInfo, found := ipFamilyInfo.clusters[localClusterID]
		if found && clusterInfo.endpointsHealthy {
			return ipFamilyInfo.newRecordFrom(&clusterInfo.endpointRecords[0]), true
		}
	}

	// Fall back to selected load balancer (weighted/RR/etc) if service is not present in the local cluster
	record := ipFamilyInfo.selectIP(i.clusterStatus.IsConnected)

	if record != nil {
		return ipFamilyInfo.newRecordFrom(record), true
	}

	return nil, true
}

func (i *Interface) getHeadlessRecords(serviceInfo *serviceInfo, ipFamily k8snet.IPFamily, clusterID, hostname string) ([]DNSRecord, bool) {
	var (
		records []DNSRecord
		found   bool
	)

	logger.Infof("getHeadlessRecords: ipFamily=%v, clusterID=%s, hostname=%s", ipFamily, clusterID, hostname)

	if ipFamily == k8snet.IPv4 {
		records, found = i.getHeadlessRecordsForIPFamily(&serviceInfo.ipv4Info, clusterID, hostname)
		logger.Infof("IPv4 only: returned %d records", len(records))
	} else if ipFamily == k8snet.IPv6 {
		records, found = i.getHeadlessRecordsForIPFamily(&serviceInfo.ipv6Info, clusterID, hostname)
		logger.Infof("IPv6 only: returned %d records", len(records))
	} else {
		logger.Infof("IPFamilyUnknown - will iterate both IPv4 and IPv6")
		for idx, ipFamilyInfo := range []*IPFamilyInfo{&serviceInfo.ipv4Info, &serviceInfo.ipv6Info} {
			logger.Infof("  Processing IP family %d (addrType=%v), clusters=%v", idx, ipFamilyInfo.addrType, len(ipFamilyInfo.clusters))
			r, f := i.getHeadlessRecordsForIPFamily(ipFamilyInfo, clusterID, hostname)
			logger.Infof("  IP family %d returned %d records, found=%v", idx, len(r), f)
			records = append(records, r...)
			found = found || f
		}
		logger.Infof("Total records after both families: %d", len(records))
	}

	return records, found
}

func (i *Interface) getHeadlessRecordsForIPFamily(ipFamilyInfo *IPFamilyInfo, clusterID, hostname string) ([]DNSRecord, bool) {
	clusterInfo, clusterFound := ipFamilyInfo.clusters[clusterID]

	logger.Infof("getHeadlessRecordsForIPFamily: addrType=%v, clusterID=%s, hostname=%s, clusterFound=%v",
		ipFamilyInfo.addrType, clusterID, hostname, clusterFound)

	switch {
	case clusterID == "":
		// Pre-allocate capacity based on total records across all clusters
		totalCapacity := 0
		for _, info := range ipFamilyInfo.clusters {
			totalCapacity += len(info.endpointRecords)
		}

		logger.Infof("  clusterID empty, total clusters=%d, totalCapacity=%d", len(ipFamilyInfo.clusters), totalCapacity)

		records := make([]DNSRecord, 0, totalCapacity)

		for id, info := range ipFamilyInfo.clusters {
			isConnected := i.clusterStatus.IsConnected(id, ipFamilyInfo.getNetIPFamily())
			logger.Infof("  Cluster %s: isConnected=%v, endpointRecords=%d", id, isConnected, len(info.endpointRecords))
			if isConnected {
				records = append(records, info.endpointRecords...)
			}
		}

		logger.Infof("  Returning %d records for addrType=%v", len(records), ipFamilyInfo.addrType)
		return records, true
	case !clusterFound:
		return nil, false
	case hostname == "":
		return clusterInfo.endpointRecords, true
	default:
		records, found := clusterInfo.endpointRecordsByHost[hostname]
		return records, found
	}
}

func keyFunc(namespace, name string) string {
	return namespace + "/" + name
}
